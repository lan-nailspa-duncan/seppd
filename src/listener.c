#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "connection.h"
#include "listener.h"
#include "log.h"
#include "sepp.h"
#include "tls_channel.h"

static void listener_clear(struct sepp_listener *listener)
{
    if (!listener)
        return;

    listener->ctx = NULL;
    listener->fd = -1;
    listener->role = SEPP_LISTENER_ROLE_NONE;
    listener->address[0] = '\0';
    listener->port = 0;
    memset(&listener->ev, 0, sizeof(listener->ev));
    listener->ev.fd = -1;
}

static int listener_set_nonblock(int fd)
{
    int flags;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return -1;

    return 0;
}

static int listener_set_cloexec(int fd)
{
    int flags;

    flags = fcntl(fd, F_GETFD, 0);
    if (flags < 0)
        return -1;

    if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0)
        return -1;

    return 0;
}

static int listener_prepare_fd(int fd)
{
    return listener_set_nonblock(fd) || listener_set_cloexec(fd);
}

static int listener_make_socket(const char *address, uint16_t port)
{
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    struct addrinfo *rp;
    char portbuf[16];
    int fd = -1;
    int rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    snprintf(portbuf, sizeof(portbuf), "%u", (unsigned int)port);

    rc = getaddrinfo(address, portbuf, &hints, &result);
    if (rc != 0) {
        SEPP_ERROR("getaddrinfo(%s:%u) failed: %s",
                   address,
                   (unsigned int)port,
                   gai_strerror(rc));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        int on = 1;

        fd = socket(rp->ai_family,
                    rp->ai_socktype,
                    rp->ai_protocol);
        if (fd < 0)
            continue;

        if (listener_prepare_fd(fd) != 0) {
            SEPP_ERROR("failed to prepare listener fd %d: %s",
                       fd,
                       strerror(errno));
            close(fd);
            fd = -1;
            continue;
        }

        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
            SEPP_ERROR("setsockopt(SO_REUSEADDR) failed: %s", strerror(errno));
            close(fd);
            fd = -1;
            continue;
        }

        if (bind(fd, rp->ai_addr, rp->ai_addrlen) != 0) {
            SEPP_ERROR("bind(%s:%u) failed: %s",
                       address,
                       (unsigned int)port,
                       strerror(errno));
            close(fd);
            fd = -1;
            continue;
        }

        if (listen(fd, SOMAXCONN) != 0) {
            SEPP_ERROR("listen(%s:%u) failed: %s",
                       address,
                       (unsigned int)port,
                       strerror(errno));
            close(fd);
            fd = -1;
            continue;
        }

        break;
    }

    freeaddrinfo(result);

    return fd;
}

static void listener_accept_cb(struct event_ctx *events,
                               struct event *ev,
                               uint32_t event_flags,
                               void *arg)
{
    struct sepp_listener *listener = arg;

    (void)events;
    (void)ev;

    if (!listener)
        return;

    if (event_flags & (EPOLLERR | EPOLLHUP)) {
        SEPP_ERROR("listener fd %d received error event 0x%x",
                   listener->fd,
                   event_flags);
        return;
    }

    for (;;) {
        struct sockaddr_storage peer_addr;
        socklen_t peer_len = sizeof(peer_addr);
        int client_fd;

        client_fd = accept(listener->fd,
                           (struct sockaddr *)&peer_addr,
                           &peer_len);
        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;

            if (errno == EINTR)
                continue;

            SEPP_ERROR("accept failed: %s", strerror(errno));
            break;
        }

        if (listener_prepare_fd(client_fd) != 0) {
            SEPP_ERROR("failed to prepare accepted fd %d: %s",
                       client_fd,
                       strerror(errno));
            close(client_fd);
            continue;
        }

        {
            struct sepp_conn *conn;

            conn = sepp_conn_accept(listener->ctx,
                                    client_fd,
                                    &peer_addr,
                                    peer_len,
                                    listener->role);
            if (!conn) {
                SEPP_ERROR("failed to create connection for fd %d", client_fd);
                close(client_fd);
                continue;
            }

            if (sepp_channel_set_tls_server(conn) != 0) {
                SEPP_ERROR("failed to attach TLS server channel to fd %d", client_fd);
                sepp_conn_destroy(listener->ctx, conn);
                continue;
            }
        }

        SEPP_INFO("accepted %s TLS connection on fd %d",
                  sepp_listener_role_name(listener->role),
                  client_fd);
    }
}

int listener_start(struct sepp_context *ctx,
                   struct sepp_listener *listener,
                   const struct sepp_listener_config *config)
{
    int fd;

    if (!ctx || !listener || !config ||
        config->role <= SEPP_LISTENER_ROLE_NONE ||
        config->role >= SEPP_LISTENER_ROLE_MAX ||
        config->address[0] == '\0' || config->port == 0)
        return -1;

    listener_clear(listener);

    fd = listener_make_socket(config->address, config->port);
    if (fd < 0)
        return -1;

    listener->ctx = ctx;
    listener->fd = fd;
    listener->role = config->role;
    listener->port = config->port;
    snprintf(listener->address,
             sizeof(listener->address),
             "%s",
             config->address);

    if (event_add(&ctx->events,
                  &listener->ev,
                  fd,
                  EPOLLIN,
                  listener_accept_cb,
                  listener) != 0) {
        close(fd);
        listener_clear(listener);
        return -1;
    }

    SEPP_INFO("%s listener active on %s:%u",
              sepp_listener_role_name(config->role),
              config->address,
              (unsigned int)config->port);

    return 0;
}

void listener_stop(struct event_ctx *events,
                   struct sepp_listener *listener)
{
    if (!listener)
        return;

    if (events && listener->ev.fd >= 0)
        event_del(events, &listener->ev);

    if (listener->fd >= 0)
        close(listener->fd);

    listener_clear(listener);
}
