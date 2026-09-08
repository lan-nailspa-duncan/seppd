#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "connection.h"
#include "log.h"
#include "object_counter.h"
#include "peer.h"
#include "sepp.h"
#include "stream.h"
#include "http2.h"

static void sepp_conn_clear(struct sepp_conn *conn)
{
    if (!conn)
        return;

    conn->fd = -1;
    memset(&conn->ev, 0, sizeof(conn->ev));
    conn->ev.fd = -1;
    conn->ctx = NULL;
    conn->listener_role = SEPP_LISTENER_ROLE_NONE;
    conn->type = SEPP_CONN_TYPE_UNKNOWN;
    sepp_channel_init(&conn->channel);
    conn->http2 = NULL;
    memset(&conn->target_key, 0, sizeof(conn->target_key));
    memset(&conn->peer_addr, 0, sizeof(conn->peer_addr));
    conn->peer_addr_len = 0;
    sepp_list_init(&conn->fd_hash_node);
    sepp_list_init(&conn->target_hash_node);
    sepp_list_init(&conn->inbound_xacts);
    sepp_list_init(&conn->outbound_xacts);
    sepp_timer_init(&conn->drain_close_timer);
    conn->flags = 0;
}

static unsigned int sepp_conn_fd_hash(int fd)
{
    return ((unsigned int)fd) % SEPP_CONN_FD_BUCKETS;
}

static void sepp_conn_event_cb(struct event_ctx *events,
                               struct event *ev,
                               uint32_t event_flags,
                               void *arg)
{
    struct sepp_conn *conn = arg;

    (void)events;
    (void)ev;

    if (!conn)
        return;

    if (sepp_channel_on_event(conn, event_flags) != 0)
        sepp_conn_destroy(conn->ctx, conn);
}

void sepp_conn_table_init(struct sepp_conn_table *table)
{
    if (!table)
        return;

    for (unsigned int i = 0; i < SEPP_CONN_FD_BUCKETS; i++)
        sepp_list_init(&table->fd_buckets[i]);

    for (unsigned int i = 0; i < SEPP_CONN_TARGET_BUCKETS; i++)
        sepp_list_init(&table->target_buckets[i]);

    table->count = 0;
}

void sepp_conn_table_destroy(struct sepp_context *ctx,
                             struct sepp_conn_table *table)
{
    if (!table)
        return;

    for (unsigned int i = 0; i < SEPP_CONN_FD_BUCKETS; i++) {
        struct sepp_list *pos;
        struct sepp_list *next;

        sepp_list_for_each_safe(pos, next, &table->fd_buckets[i]) {
            struct sepp_conn *conn;

            conn = sepp_list_entry(pos, struct sepp_conn, fd_hash_node);
            sepp_conn_destroy(ctx, conn);
        }
    }
}

struct sepp_conn *sepp_conn_lookup_fd(struct sepp_conn_table *table, int fd)
{
    struct sepp_list *pos;
    unsigned int bucket;

    if (!table || fd < 0)
        return NULL;

    bucket = sepp_conn_fd_hash(fd);

    sepp_list_for_each(pos, &table->fd_buckets[bucket]) {
        struct sepp_conn *conn;

        conn = sepp_list_entry(pos, struct sepp_conn, fd_hash_node);
        if (conn->fd == fd)
            return conn;
    }

    return NULL;
}


const char *sepp_conn_type_name(enum sepp_conn_type type)
{
    switch (type) {
    case SEPP_CONN_TYPE_N32C:
        return "n32c";
    case SEPP_CONN_TYPE_N32F:
        return "n32f";
    case SEPP_CONN_TYPE_INTERNAL_NF:
        return "internal-nf";
    case SEPP_CONN_TYPE_SCP:
        return "scp";
    case SEPP_CONN_TYPE_UNKNOWN:
    default:
        return "unknown";
    }
}

void sepp_conn_set_type(struct sepp_conn *conn, enum sepp_conn_type type)
{
    if (!conn)
        return;

    conn->type = type;
}

struct sepp_conn *sepp_conn_lookup_target_type(struct sepp_conn_table *table,
                                               const struct sepp_target_key *key,
                                               enum sepp_conn_type type)
{
    struct sepp_list *pos;
    struct sepp_conn *standby = NULL;
    unsigned int bucket;

    if (!table || !key || type == SEPP_CONN_TYPE_UNKNOWN)
        return NULL;

    bucket = sepp_target_hash(key) % SEPP_CONN_TARGET_BUCKETS;

    sepp_list_for_each(pos, &table->target_buckets[bucket]) {
        struct sepp_conn *conn;

        conn = sepp_list_entry(pos, struct sepp_conn, target_hash_node);
        /* Target/type lookup is used to reuse locally initiated channels.
         * An inbound HTTP/2 server connection cannot be reused as a client
         * channel, even when it is correlated with the same peer target. */
        if ((conn->flags & SEPP_CONN_F_HAS_TARGET) &&
            (conn->flags & SEPP_CONN_F_OUTBOUND) &&
            sepp_target_equal(&conn->target_key, key) &&
            conn->type == type) {
            if (conn->flags & SEPP_CONN_F_DRAINING)
                continue;

            if (conn->flags & SEPP_CONN_F_STANDBY) {
                standby = conn;
                continue;
            }

            return conn;
        }
    }

    return standby;
}


struct sepp_conn *sepp_conn_add_socket(struct sepp_context *ctx,
                                         int fd,
                                         const struct sockaddr_storage *peer_addr,
                                         socklen_t peer_addr_len,
                                         uint32_t flags)
{
    struct sepp_conn *conn;
    unsigned int bucket;
    uint32_t event_flags = EPOLLIN | EPOLLRDHUP;

    if (!ctx || fd < 0 || !peer_addr)
        return NULL;

    if (sepp_conn_lookup_fd(&ctx->conn_table, fd)) {
        SEPP_ERROR("connection fd %d already exists", fd);
        return NULL;
    }

    conn = calloc(1, sizeof(*conn));
    if (!conn)
        return NULL;
    sepp_object_counter_alloc(SEPP_OBJECT_CONNECTION);

    sepp_conn_clear(conn);

    conn->fd = fd;
    conn->ctx = ctx;
    memcpy(&conn->peer_addr, peer_addr, sizeof(conn->peer_addr));
    conn->peer_addr_len = peer_addr_len;
    conn->flags = flags;

    if (sepp_channel_set_plain_tcp(conn) != 0) {
        sepp_object_counter_free(SEPP_OBJECT_CONNECTION);
        free(conn);
        return NULL;
    }

    if (flags & SEPP_CONN_F_CONNECTING)
        event_flags |= EPOLLOUT;

    if (event_add(&ctx->events,
                  &conn->ev,
                  fd,
                  event_flags,
                  sepp_conn_event_cb,
                  conn) != 0) {
        sepp_object_counter_free(SEPP_OBJECT_CONNECTION);
        free(conn);
        return NULL;
    }

    bucket = sepp_conn_fd_hash(fd);
    sepp_list_add_tail(&conn->fd_hash_node,
                       &ctx->conn_table.fd_buckets[bucket]);
    ctx->conn_table.count++;

    SEPP_INFO("connection fd %d added", fd);

    return conn;
}

struct sepp_conn *sepp_conn_accept(struct sepp_context *ctx,
                                   int fd,
                                   const struct sockaddr_storage *peer_addr,
                                   socklen_t peer_addr_len,
                                   enum sepp_listener_role listener_role)
{
    struct sepp_conn *conn;

    if (listener_role != SEPP_LISTENER_ROLE_INTERNAL_SBI &&
        listener_role != SEPP_LISTENER_ROLE_EXTERNAL_N32)
        return NULL;

    conn = sepp_conn_add_socket(ctx, fd, peer_addr, peer_addr_len, 0);
    if (!conn)
        return NULL;

    conn->listener_role = listener_role;
    if (listener_role == SEPP_LISTENER_ROLE_INTERNAL_SBI)
        sepp_conn_set_type(conn, SEPP_CONN_TYPE_INTERNAL_NF);

    SEPP_INFO("accepted fd %d classified as %s on %s listener",
              fd,
              sepp_conn_type_name(conn->type),
              sepp_listener_role_name(listener_role));

    return conn;
}

int sepp_conn_set_target(struct sepp_conn_table *table,
                         struct sepp_conn *conn,
                         const struct sepp_target_key *key)
{
    unsigned int bucket;

    if (!table || !conn || !key || key->type == SEPP_TARGET_NONE)
        return -1;

    if (conn->flags & SEPP_CONN_F_HAS_TARGET) {
        sepp_list_del(&conn->target_hash_node);
        conn->flags &= ~SEPP_CONN_F_HAS_TARGET;
        memset(&conn->target_key, 0, sizeof(conn->target_key));
    }

    if (!(conn->type == SEPP_CONN_TYPE_N32F &&
          (conn->flags & SEPP_CONN_F_STANDBY)) &&
        sepp_conn_lookup_target_type(table, key, conn->type)) {
        SEPP_ERROR("%s target connection already exists for %s",
                   sepp_conn_type_name(conn->type),
                   key->fqdn);
        return -1;
    }

    memcpy(&conn->target_key, key, sizeof(conn->target_key));
    bucket = sepp_target_hash(key) % SEPP_CONN_TARGET_BUCKETS;
    sepp_list_add_tail(&conn->target_hash_node,
                       &table->target_buckets[bucket]);
    conn->flags |= SEPP_CONN_F_HAS_TARGET;

    return 0;
}

void sepp_conn_destroy(struct sepp_context *ctx, struct sepp_conn *conn)
{
    struct sepp_conn_table *table;
    int fd;

    if (!conn)
        return;

    if (conn->flags & SEPP_CONN_F_DESTROYING)
        return;

    conn->flags |= SEPP_CONN_F_DESTROYING;

    table = ctx ? &ctx->conn_table : NULL;
    fd = conn->fd;

    if (ctx && sepp_timer_active(&conn->drain_close_timer))
        sepp_timer_stop(ctx, &conn->drain_close_timer);

    if (ctx)
        sepp_stream_remove_conn(ctx, conn);

    if (ctx && conn->ev.fd >= 0)
        event_del(&ctx->events, &conn->ev);

    sepp_http2_destroy(conn);
    sepp_channel_cleanup(conn);

    if (ctx)
        sepp_peer_detach_conn(&ctx->peer_table, conn);

    if (!sepp_list_empty(&conn->target_hash_node)) {
        sepp_list_del(&conn->target_hash_node);
        conn->flags &= ~SEPP_CONN_F_HAS_TARGET;
    }

    if (!sepp_list_empty(&conn->fd_hash_node)) {
        sepp_list_del(&conn->fd_hash_node);
        if (table && table->count > 0)
            table->count--;
    }

    if (fd >= 0)
        close(fd);

    SEPP_INFO("connection fd %d destroyed", fd);

    sepp_object_counter_free(SEPP_OBJECT_CONNECTION);
    free(conn);
}
