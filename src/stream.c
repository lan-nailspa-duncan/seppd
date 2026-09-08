#include <stdlib.h>

#include "connection.h"
#include "log.h"
#include "object_counter.h"
#include "sepp.h"
#include "stream.h"
#include "target_manager.h"

static unsigned int sepp_stream_hash(int fd, int32_t stream_id)
{
    unsigned int hash;

    hash = (unsigned int)fd;
    hash = (hash * 31u) ^ (unsigned int)stream_id;

    return hash % SEPP_STREAM_BUCKETS;
}

static void sepp_stream_xact_init(struct sepp_stream_xact *xact)
{
    xact->in_conn = NULL;
    xact->in_stream_id = 0;
    xact->out_conn = NULL;
    xact->out_stream_id = 0;
    sepp_list_init(&xact->in_conn_node);
    sepp_list_init(&xact->out_conn_node);
    sepp_list_init(&xact->in_hash_node);
    sepp_list_init(&xact->out_hash_node);
}

void sepp_stream_table_init(struct sepp_stream_table *table)
{
    if (!table)
        return;

    for (unsigned int i = 0; i < SEPP_STREAM_BUCKETS; i++) {
        sepp_list_init(&table->in_buckets[i]);
        sepp_list_init(&table->out_buckets[i]);
    }

    table->count = 0;
}

void sepp_stream_table_destroy(struct sepp_context *ctx,
                               struct sepp_stream_table *table)
{
    if (!ctx || !table)
        return;

    for (unsigned int i = 0; i < SEPP_STREAM_BUCKETS; i++) {
        struct sepp_list *pos;
        struct sepp_list *next;

        sepp_list_for_each_safe(pos, next, &table->in_buckets[i]) {
            struct sepp_stream_xact *xact;

            xact = sepp_list_entry(pos,
                                   struct sepp_stream_xact,
                                   in_hash_node);
            sepp_stream_destroy(ctx, xact);
        }
    }
}

struct sepp_stream_xact *sepp_stream_lookup_in(struct sepp_stream_table *table,
                                               const struct sepp_conn *conn,
                                               int32_t stream_id)
{
    struct sepp_list *pos;
    unsigned int bucket;

    if (!table || !conn || conn->fd < 0 || stream_id <= 0)
        return NULL;

    bucket = sepp_stream_hash(conn->fd, stream_id);

    sepp_list_for_each(pos, &table->in_buckets[bucket]) {
        struct sepp_stream_xact *xact;

        xact = sepp_list_entry(pos,
                               struct sepp_stream_xact,
                               in_hash_node);
        if (xact->in_conn == conn && xact->in_stream_id == stream_id)
            return xact;
    }

    return NULL;
}

struct sepp_stream_xact *sepp_stream_lookup_out(struct sepp_stream_table *table,
                                                const struct sepp_conn *conn,
                                                int32_t stream_id)
{
    struct sepp_list *pos;
    unsigned int bucket;

    if (!table || !conn || conn->fd < 0 || stream_id <= 0)
        return NULL;

    bucket = sepp_stream_hash(conn->fd, stream_id);

    sepp_list_for_each(pos, &table->out_buckets[bucket]) {
        struct sepp_stream_xact *xact;

        xact = sepp_list_entry(pos,
                               struct sepp_stream_xact,
                               out_hash_node);
        if (xact->out_conn == conn && xact->out_stream_id == stream_id)
            return xact;
    }

    return NULL;
}

struct sepp_stream_xact *sepp_stream_create(struct sepp_context *ctx,
                                            struct sepp_conn *in_conn,
                                            int32_t in_stream_id,
                                            struct sepp_conn *out_conn,
                                            int32_t out_stream_id)
{
    struct sepp_stream_xact *xact;
    unsigned int in_bucket;
    unsigned int out_bucket;

    if (!ctx || !in_conn || !out_conn ||
        in_conn->fd < 0 || out_conn->fd < 0 ||
        in_stream_id <= 0 || out_stream_id <= 0)
        return NULL;

    if (sepp_stream_lookup_in(&ctx->stream_table, in_conn, in_stream_id)) {
        SEPP_ERROR("inbound stream mapping already exists: fd %d stream %d",
                   in_conn->fd,
                   in_stream_id);
        return NULL;
    }

    if (sepp_stream_lookup_out(&ctx->stream_table, out_conn, out_stream_id)) {
        SEPP_ERROR("outbound stream mapping already exists: fd %d stream %d",
                   out_conn->fd,
                   out_stream_id);
        return NULL;
    }

    xact = calloc(1, sizeof(*xact));
    if (!xact)
        return NULL;
    sepp_object_counter_alloc(SEPP_OBJECT_STREAM_TRANSACTION);

    sepp_stream_xact_init(xact);

    xact->in_conn = in_conn;
    xact->in_stream_id = in_stream_id;
    xact->out_conn = out_conn;
    xact->out_stream_id = out_stream_id;

    in_bucket = sepp_stream_hash(in_conn->fd, in_stream_id);
    out_bucket = sepp_stream_hash(out_conn->fd, out_stream_id);

    sepp_list_add_tail(&xact->in_hash_node,
                       &ctx->stream_table.in_buckets[in_bucket]);
    sepp_list_add_tail(&xact->out_hash_node,
                       &ctx->stream_table.out_buckets[out_bucket]);

    sepp_list_add_tail(&xact->in_conn_node, &in_conn->inbound_xacts);
    sepp_list_add_tail(&xact->out_conn_node, &out_conn->outbound_xacts);

    ctx->stream_table.count++;

    SEPP_DEBUG("stream mapping created: in fd %d stream %d -> out fd %d stream %d",
               in_conn->fd,
               in_stream_id,
               out_conn->fd,
               out_stream_id);

    return xact;
}

void sepp_stream_destroy(struct sepp_context *ctx,
                         struct sepp_stream_xact *xact)
{
    struct sepp_conn *in_conn;
    struct sepp_conn *out_conn;

    if (!ctx || !xact)
        return;

    in_conn = xact->in_conn;
    out_conn = xact->out_conn;

    if (!sepp_list_empty(&xact->in_hash_node))
        sepp_list_del(&xact->in_hash_node);

    if (!sepp_list_empty(&xact->out_hash_node))
        sepp_list_del(&xact->out_hash_node);

    if (!sepp_list_empty(&xact->in_conn_node))
        sepp_list_del(&xact->in_conn_node);

    if (!sepp_list_empty(&xact->out_conn_node))
        sepp_list_del(&xact->out_conn_node);

    if (ctx->stream_table.count > 0)
        ctx->stream_table.count--;

    sepp_object_counter_free(SEPP_OBJECT_STREAM_TRANSACTION);
    free(xact);

    if (in_conn &&
        (in_conn->flags & SEPP_CONN_F_DRAINING) &&
        !(in_conn->flags & SEPP_CONN_F_DESTROYING))
        (void)sepp_target_maybe_close_draining_n32f(in_conn);

    if (out_conn &&
        (out_conn->flags & SEPP_CONN_F_DRAINING) &&
        !(out_conn->flags & SEPP_CONN_F_DESTROYING))
        (void)sepp_target_maybe_close_draining_n32f(out_conn);
}

void sepp_stream_remove_conn(struct sepp_context *ctx,
                             struct sepp_conn *conn)
{
    struct sepp_list *pos;
    struct sepp_list *next;

    if (!ctx || !conn)
        return;

    sepp_list_for_each_safe(pos, next, &conn->inbound_xacts) {
        struct sepp_stream_xact *xact;

        xact = sepp_list_entry(pos,
                               struct sepp_stream_xact,
                               in_conn_node);
        sepp_stream_destroy(ctx, xact);
    }

    sepp_list_for_each_safe(pos, next, &conn->outbound_xacts) {
        struct sepp_stream_xact *xact;

        xact = sepp_list_entry(pos,
                               struct sepp_stream_xact,
                               out_conn_node);
        sepp_stream_destroy(ctx, xact);
    }
}
