#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "ipc.h"
#include "log.h"
#include "sepp.h"

struct sepp_ipc_frame {
    struct sepp_ipc_msg_hdr hdr;
    unsigned char payload[SEPP_IPC_MAX_PAYLOAD];
};

static int ipc_set_nonblock(int fd)
{
    int flags;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return -1;

    return 0;
}

static int ipc_set_cloexec(int fd)
{
    int flags;

    flags = fcntl(fd, F_GETFD, 0);
    if (flags < 0)
        return -1;

    if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0)
        return -1;

    return 0;
}

static int ipc_prepare_fd(int fd)
{
    return ipc_set_nonblock(fd) || ipc_set_cloexec(fd);
}

static int ipc_fill_sockaddr(struct sockaddr_un *addr,
                             socklen_t *addr_len,
                             const char *path)
{
    size_t path_len;

    if (!addr || !addr_len || !path || path[0] == '\0')
        return -1;

    path_len = strlen(path);
    if (path_len >= sizeof(addr->sun_path))
        return -1;

    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    memcpy(addr->sun_path, path, path_len + 1u);
    *addr_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                            path_len + 1u);

    return 0;
}

static void ipc_pending_timeout(struct sepp_pending *pending, void *arg)
{
    struct sepp_ipc_req *req;

    (void)arg;

    if (!pending)
        return;

    req = sepp_container_of(pending, struct sepp_ipc_req, pending);

    if (!sepp_list_empty(&req->client_node))
        sepp_list_del(&req->client_node);

    if (req->timeout_cb)
        req->timeout_cb(req->client, req, req->arg);

    sepp_ipc_req_init(req);
}

static void ipc_handle_response(struct sepp_ipc_client *client,
                                const struct sepp_ipc_msg_hdr *hdr,
                                const void *payload,
                                size_t payload_len)
{
    struct sepp_pending *pending;
    struct sepp_ipc_req *req;

    pending = sepp_pending_lookup(&client->ctx->pending_mgr,
                                  hdr->request_id);
    if (!pending) {
        SEPP_DEBUG("ipc response for unknown request %llu",
                   (unsigned long long)hdr->request_id);
        return;
    }

    req = sepp_container_of(pending, struct sepp_ipc_req, pending);
    if (req->client != client) {
        SEPP_ERROR("ipc response %llu delivered to wrong client",
                   (unsigned long long)hdr->request_id);
        return;
    }

    if (req->response_type != 0 && hdr->type != req->response_type) {
        SEPP_ERROR("ipc response %llu has unexpected type %u, expected %u",
                   (unsigned long long)hdr->request_id,
                   hdr->type,
                   req->response_type);
        return;
    }

    sepp_pending_remove(client->ctx, &req->pending);

    if (!sepp_list_empty(&req->client_node))
        sepp_list_del(&req->client_node);

    if (req->response_cb)
        req->response_cb(client, req, payload, payload_len, req->arg);

    sepp_ipc_req_init(req);
}

static int ipc_read_one(struct sepp_ipc_client *client)
{
    struct sepp_ipc_frame frame;
    ssize_t nread;
    size_t header_len = sizeof(frame.hdr);

    nread = recv(client->fd, &frame, sizeof(frame), 0);
    if (nread < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;

        if (errno == EINTR)
            return 1;

        SEPP_ERROR("ipc recv failed: %s", strerror(errno));
        return -1;
    }

    if ((size_t)nread < header_len) {
        SEPP_ERROR("short ipc message received: %zd", nread);
        return 1;
    }

    if (frame.hdr.magic != SEPP_IPC_MAGIC ||
        frame.hdr.version != SEPP_IPC_VERSION) {
        SEPP_ERROR("invalid ipc header received");
        return 1;
    }

    if (frame.hdr.payload_len > SEPP_IPC_MAX_PAYLOAD ||
        (size_t)nread != header_len + frame.hdr.payload_len) {
        SEPP_ERROR("invalid ipc payload length %u", frame.hdr.payload_len);
        return 1;
    }

    ipc_handle_response(client,
                        &frame.hdr,
                        frame.payload,
                        frame.hdr.payload_len);

    return 1;
}

static void ipc_event_cb(struct event_ctx *events,
                         struct event *ev,
                         uint32_t event_flags,
                         void *arg)
{
    struct sepp_ipc_client *client = arg;

    (void)events;
    (void)ev;

    if (!client)
        return;

    if (event_flags & (EPOLLERR | EPOLLHUP)) {
        SEPP_ERROR("ipc socket event error: 0x%x", event_flags);
        return;
    }

    if (!(event_flags & EPOLLIN))
        return;

    for (;;) {
        int rc;

        rc = ipc_read_one(client);
        if (rc <= 0)
            break;
    }
}

void sepp_ipc_req_init(struct sepp_ipc_req *req)
{
    if (!req)
        return;

    sepp_pending_init(&req->pending);
    req->client = NULL;
    sepp_list_init(&req->client_node);
    req->response_type = 0;
    req->response_cb = NULL;
    req->timeout_cb = NULL;
    req->arg = NULL;
}

int sepp_ipc_client_init(struct sepp_context *ctx,
                         struct sepp_ipc_client *client,
                         const char *local_path,
                         const char *peer_path)
{
    int fd;

    if (!ctx || !client || !peer_path)
        return -1;

    memset(client, 0, sizeof(*client));
    client->ctx = ctx;
    client->fd = -1;
    client->ev.fd = -1;
    sepp_list_init(&client->reqs);

    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        SEPP_ERROR("ipc socket create failed: %s", strerror(errno));
        return -1;
    }

    if (ipc_prepare_fd(fd) != 0) {
        SEPP_ERROR("ipc socket prepare failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    if (local_path && local_path[0] != '\0') {
        struct sockaddr_un local_addr;
        socklen_t local_len;

        if (ipc_fill_sockaddr(&local_addr, &local_len, local_path) != 0) {
            close(fd);
            return -1;
        }

        (void)unlink(local_path);

        if (bind(fd, (struct sockaddr *)&local_addr, local_len) != 0) {
            SEPP_ERROR("ipc bind(%s) failed: %s",
                       local_path,
                       strerror(errno));
            close(fd);
            return -1;
        }
    }

    if (ipc_fill_sockaddr(&client->peer_addr,
                          &client->peer_addr_len,
                          peer_path) != 0) {
        close(fd);
        return -1;
    }

    client->fd = fd;

    if (event_add(&ctx->events,
                  &client->ev,
                  fd,
                  EPOLLIN,
                  ipc_event_cb,
                  client) != 0) {
        close(fd);
        client->fd = -1;
        return -1;
    }

    SEPP_DEBUG("ipc client initialized for peer %s", peer_path);

    return 0;
}

void sepp_ipc_client_cleanup(struct sepp_ipc_client *client)
{
    int fd;

    if (!client)
        return;

    if (client->ctx) {
        struct sepp_list *pos;
        struct sepp_list *next;

        sepp_list_for_each_safe(pos, next, &client->reqs) {
            struct sepp_ipc_req *req;

            req = sepp_list_entry(pos, struct sepp_ipc_req, client_node);
            sepp_ipc_cancel_request(client, req);
        }
    }

    fd = client->fd;

    if (client->ctx && client->ev.fd >= 0)
        event_del(&client->ctx->events, &client->ev);

    if (fd >= 0)
        close(fd);

    client->fd = -1;
    client->ev.fd = -1;
    client->ctx = NULL;
    memset(&client->peer_addr, 0, sizeof(client->peer_addr));
    client->peer_addr_len = 0;
}

int sepp_ipc_send_request_type(struct sepp_ipc_client *client,
                               struct sepp_ipc_req *req,
                               uint16_t request_type,
                               uint16_t response_type,
                               const void *payload,
                               size_t payload_len,
                               uint64_t timeout_ms,
                               sepp_ipc_response_cb response_cb,
                               sepp_ipc_timeout_cb timeout_cb,
                               void *arg)
{
    struct sepp_ipc_frame frame;
    uint64_t request_id;
    size_t frame_len;
    ssize_t nsent;

    if (!client || !client->ctx || client->fd < 0 || !req)
        return -1;

    if (request_type == 0 || response_type == 0)
        return -1;

    if (payload_len > SEPP_IPC_MAX_PAYLOAD)
        return -1;

    if (payload_len > 0 && !payload)
        return -1;

    if (req->pending.active)
        return -1;

    request_id = sepp_pending_alloc_id(&client->ctx->pending_mgr);
    if (request_id == 0)
        return -1;

    memset(&frame, 0, sizeof(frame));
    frame.hdr.magic = SEPP_IPC_MAGIC;
    frame.hdr.version = SEPP_IPC_VERSION;
    frame.hdr.type = request_type;
    frame.hdr.request_id = request_id;
    frame.hdr.payload_len = (uint32_t)payload_len;

    if (payload_len > 0)
        memcpy(frame.payload, payload, payload_len);

    sepp_ipc_req_init(req);
    req->client = client;
    req->response_type = response_type;
    req->response_cb = response_cb;
    req->timeout_cb = timeout_cb;
    req->arg = arg;

    sepp_list_add_tail(&req->client_node, &client->reqs);

    if (sepp_pending_add(client->ctx,
                         &client->ctx->pending_mgr,
                         &req->pending,
                         request_id,
                         timeout_ms,
                         ipc_pending_timeout,
                         NULL) != 0) {
        if (!sepp_list_empty(&req->client_node))
            sepp_list_del(&req->client_node);
        sepp_ipc_req_init(req);
        return -1;
    }

    frame_len = sizeof(frame.hdr) + payload_len;
    nsent = sendto(client->fd,
                   &frame,
                   frame_len,
                   0,
                   (const struct sockaddr *)&client->peer_addr,
                   client->peer_addr_len);
    if (nsent < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            SEPP_ERROR("ipc sendto failed: %s", strerror(errno));
        sepp_pending_remove(client->ctx, &req->pending);
        if (!sepp_list_empty(&req->client_node))
            sepp_list_del(&req->client_node);
        sepp_ipc_req_init(req);
        return -1;
    }

    if ((size_t)nsent != frame_len) {
        SEPP_ERROR("short ipc send: %zd/%zu", nsent, frame_len);
        sepp_pending_remove(client->ctx, &req->pending);
        if (!sepp_list_empty(&req->client_node))
            sepp_list_del(&req->client_node);
        sepp_ipc_req_init(req);
        return -1;
    }

    return 0;
}

int sepp_ipc_send_request(struct sepp_ipc_client *client,
                          struct sepp_ipc_req *req,
                          const void *payload,
                          size_t payload_len,
                          uint64_t timeout_ms,
                          sepp_ipc_response_cb response_cb,
                          sepp_ipc_timeout_cb timeout_cb,
                          void *arg)
{
    return sepp_ipc_send_request_type(client,
                                      req,
                                      SEPP_IPC_MSG_REQUEST,
                                      SEPP_IPC_MSG_RESPONSE,
                                      payload,
                                      payload_len,
                                      timeout_ms,
                                      response_cb,
                                      timeout_cb,
                                      arg);
}

void sepp_ipc_cancel_request(struct sepp_ipc_client *client,
                             struct sepp_ipc_req *req)
{
    if (!client || !client->ctx || !req)
        return;

    sepp_pending_remove(client->ctx, &req->pending);
    if (!sepp_list_empty(&req->client_node))
        sepp_list_del(&req->client_node);
    sepp_ipc_req_init(req);
}
