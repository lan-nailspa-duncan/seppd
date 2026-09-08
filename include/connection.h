#ifndef CONNECTION_H
#define CONNECTION_H

#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>

#include "config.h"
#include "event.h"
#include "list.h"
#include "channel.h"
#include "target.h"
#include "timer.h"

struct sepp_context;
struct sepp_http2;

#define SEPP_CONN_F_HAS_TARGET 0x00000001u
#define SEPP_CONN_F_CONNECTING  0x00000002u
#define SEPP_CONN_F_OUTBOUND    0x00000004u
#define SEPP_CONN_F_TLS          0x00000008u
#define SEPP_CONN_F_TLS_SERVER   0x00000010u
#define SEPP_CONN_F_TLS_CLIENT   0x00000020u
#define SEPP_CONN_F_CERT_VERIFY  0x00000040u
#define SEPP_CONN_F_ESTABLISHED  0x00000080u
#define SEPP_CONN_F_STANDBY      0x00000100u
#define SEPP_CONN_F_DRAINING     0x00000200u
#define SEPP_CONN_F_DESTROYING   0x00000400u
#define SEPP_CONN_F_TEARDOWN     0x00000800u

#define SEPP_CONN_FD_BUCKETS     256u
#define SEPP_CONN_TARGET_BUCKETS 256u

enum sepp_conn_type {
    SEPP_CONN_TYPE_UNKNOWN = 0,
    SEPP_CONN_TYPE_N32C,
    SEPP_CONN_TYPE_N32F,
    SEPP_CONN_TYPE_INTERNAL_NF,
    SEPP_CONN_TYPE_SCP,
};

struct sepp_conn {
    int fd;
    struct event ev;
    struct sepp_context *ctx;
    enum sepp_listener_role listener_role;
    enum sepp_conn_type type;
    struct sepp_channel channel;
    struct sepp_http2 *http2;

    struct sepp_target_key target_key;

    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;

    struct sepp_list fd_hash_node;
    struct sepp_list target_hash_node;

    struct sepp_list inbound_xacts;
    struct sepp_list outbound_xacts;
    struct sepp_timer drain_close_timer;

    uint32_t flags;
};

struct sepp_conn_table {
    struct sepp_list fd_buckets[SEPP_CONN_FD_BUCKETS];
    struct sepp_list target_buckets[SEPP_CONN_TARGET_BUCKETS];
    unsigned int count;
};

void sepp_conn_table_init(struct sepp_conn_table *table);
void sepp_conn_table_destroy(struct sepp_context *ctx,
                             struct sepp_conn_table *table);

struct sepp_conn *sepp_conn_lookup_fd(struct sepp_conn_table *table, int fd);
struct sepp_conn *sepp_conn_lookup_target_type(struct sepp_conn_table *table,
                                               const struct sepp_target_key *key,
                                               enum sepp_conn_type type);

const char *sepp_conn_type_name(enum sepp_conn_type type);
void sepp_conn_set_type(struct sepp_conn *conn, enum sepp_conn_type type);

struct sepp_conn *sepp_conn_add_socket(struct sepp_context *ctx,
                                         int fd,
                                         const struct sockaddr_storage *peer_addr,
                                         socklen_t peer_addr_len,
                                         uint32_t flags);

struct sepp_conn *sepp_conn_accept(struct sepp_context *ctx,
                                   int fd,
                                   const struct sockaddr_storage *peer_addr,
                                   socklen_t peer_addr_len,
                                   enum sepp_listener_role listener_role);

int sepp_conn_set_target(struct sepp_conn_table *table,
                         struct sepp_conn *conn,
                         const struct sepp_target_key *key);

void sepp_conn_destroy(struct sepp_context *ctx, struct sepp_conn *conn);

#endif
