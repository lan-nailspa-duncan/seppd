#ifndef TARGET_MANAGER_H
#define TARGET_MANAGER_H

#include "config.h"
#include "target.h"

struct sepp_conn;
struct sepp_context;
struct sepp_peer_ctx;

enum sepp_target_status {
    SEPP_TARGET_STATUS_READY = 0,
    SEPP_TARGET_STATUS_CONNECTING,
    SEPP_TARGET_STATUS_NEEDS_N32C,
    SEPP_TARGET_STATUS_FAILED,
};

struct sepp_target_status_info {
    enum sepp_target_status status;
    struct sepp_conn *conn;
    struct sepp_peer_ctx *peer;
};

const char *sepp_target_status_name(enum sepp_target_status status);

int sepp_target_conn_ready(const struct sepp_conn *conn);

int sepp_target_start_n32c(struct sepp_context *ctx,
                            const struct sepp_target_key *key);

int sepp_target_start_n32f_replacement(struct sepp_context *ctx,
                                       const struct sepp_target_key *key);

int sepp_target_n32f_conn_ready(struct sepp_context *ctx,
                                struct sepp_conn *conn);

int sepp_target_maybe_close_draining_n32f(struct sepp_conn *conn);

int sepp_target_drain_n32f_connections(
    struct sepp_context *ctx,
    const struct sepp_target_key *key);

void sepp_target_get_status(struct sepp_context *ctx,
                            const struct sepp_target_key *key,
                            const struct sepp_target_config *cfg,
                            struct sepp_conn *conn,
                            struct sepp_target_status_info *info);

#endif /* TARGET_MANAGER_H */
