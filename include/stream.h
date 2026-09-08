#ifndef STREAM_H
#define STREAM_H

#include <stdint.h>

#include "list.h"

struct sepp_conn;
struct sepp_context;

#define SEPP_STREAM_BUCKETS 256u

struct sepp_stream_key {
    int fd;
    int32_t stream_id;
};

struct sepp_stream_xact {
    struct sepp_conn *in_conn;
    int32_t in_stream_id;

    struct sepp_conn *out_conn;
    int32_t out_stream_id;

    struct sepp_list in_conn_node;
    struct sepp_list out_conn_node;

    struct sepp_list in_hash_node;
    struct sepp_list out_hash_node;
};

struct sepp_stream_table {
    struct sepp_list in_buckets[SEPP_STREAM_BUCKETS];
    struct sepp_list out_buckets[SEPP_STREAM_BUCKETS];
    unsigned int count;
};

void sepp_stream_table_init(struct sepp_stream_table *table);
void sepp_stream_table_destroy(struct sepp_context *ctx,
                               struct sepp_stream_table *table);

struct sepp_stream_xact *sepp_stream_create(struct sepp_context *ctx,
                                            struct sepp_conn *in_conn,
                                            int32_t in_stream_id,
                                            struct sepp_conn *out_conn,
                                            int32_t out_stream_id);

void sepp_stream_destroy(struct sepp_context *ctx,
                         struct sepp_stream_xact *xact);

struct sepp_stream_xact *sepp_stream_lookup_in(struct sepp_stream_table *table,
                                               const struct sepp_conn *conn,
                                               int32_t stream_id);

struct sepp_stream_xact *sepp_stream_lookup_out(struct sepp_stream_table *table,
                                                const struct sepp_conn *conn,
                                                int32_t stream_id);

void sepp_stream_remove_conn(struct sepp_context *ctx,
                             struct sepp_conn *conn);

#endif
