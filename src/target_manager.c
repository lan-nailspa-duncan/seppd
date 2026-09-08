#include <string.h>

#include "connection.h"
#include "connector.h"
#include "log.h"
#include "http2.h"
#include "peer.h"
#include "sepp.h"
#include "target_manager.h"

#define SEPP_N32F_TEARDOWN_DRAIN_TIMEOUT_MS 30000u

const char *sepp_target_status_name(enum sepp_target_status status)
{
    switch (status) {
    case SEPP_TARGET_STATUS_READY:
        return "ready";
    case SEPP_TARGET_STATUS_CONNECTING:
        return "connecting";
    case SEPP_TARGET_STATUS_NEEDS_N32C:
        return "needs-n32c";
    case SEPP_TARGET_STATUS_FAILED:
    default:
        return "failed";
    }
}

int sepp_target_conn_ready(const struct sepp_conn *conn)
{
    if (!conn)
        return 0;

    if (conn->flags & SEPP_CONN_F_CONNECTING)
        return 0;

    if (!(conn->flags & SEPP_CONN_F_ESTABLISHED))
        return 0;

    if (!conn->http2)
        return 0;

    return 1;
}

static void target_status_set(struct sepp_target_status_info *info,
                              enum sepp_target_status status,
                              struct sepp_conn *conn,
                              struct sepp_peer_ctx *peer)
{
    if (!info)
        return;

    info->status = status;
    info->conn = conn;
    info->peer = peer;
}

static void target_peer_status(struct sepp_context *ctx,
                               const struct sepp_target_key *key,
                               struct sepp_conn *conn,
                               struct sepp_target_status_info *info)
{
    struct sepp_peer_ctx *peer;

    if (!ctx || !key) {
        target_status_set(info, SEPP_TARGET_STATUS_FAILED, conn, NULL);
        return;
    }

    peer = sepp_peer_lookup_target(&ctx->peer_table, key);
    if (!peer) {
        target_status_set(info, SEPP_TARGET_STATUS_FAILED, conn, NULL);
        return;
    }

    if (peer->n32c_state != SEPP_N32C_STATE_ESTABLISHED) {
        target_status_set(info, SEPP_TARGET_STATUS_NEEDS_N32C, conn, peer);
        return;
    }

    if (!peer->n32f_conn) {
        target_status_set(info, SEPP_TARGET_STATUS_CONNECTING, conn, peer);
        return;
    }

    if (conn && conn != peer->n32f_conn) {
        target_status_set(info, SEPP_TARGET_STATUS_CONNECTING, conn, peer);
        return;
    }

    if (!sepp_target_conn_ready(peer->n32f_conn)) {
        target_status_set(info, SEPP_TARGET_STATUS_CONNECTING, peer->n32f_conn, peer);
        return;
    }

    target_status_set(info, SEPP_TARGET_STATUS_READY, peer->n32f_conn, peer);
}

static void target_plain_status(struct sepp_conn *conn,
                                struct sepp_target_status_info *info)
{
    if (!conn) {
        target_status_set(info, SEPP_TARGET_STATUS_CONNECTING, NULL, NULL);
        return;
    }

    if (!sepp_target_conn_ready(conn)) {
        target_status_set(info, SEPP_TARGET_STATUS_CONNECTING, conn, NULL);
        return;
    }

    target_status_set(info, SEPP_TARGET_STATUS_READY, conn, NULL);
}

int sepp_target_start_n32c(struct sepp_context *ctx,
                            const struct sepp_target_key *key)
{
    struct sepp_peer_ctx *peer;
    struct sepp_conn *conn;

    if (!ctx || !key || key->type != SEPP_TARGET_PEER_SEPP)
        return -1;

    peer = sepp_peer_lookup_target(&ctx->peer_table, key);
    if (!peer)
        return -1;

    if (peer->n32c_state == SEPP_N32C_STATE_ESTABLISHED)
        return 0;

    if (peer->n32c_conn)
        return 0;

    conn = sepp_connector_get_or_connect_type(ctx,
                                              key,
                                              peer->n32c_peer_fqdn,
                                              peer->n32c_peer_port,
                                              SEPP_CONN_TYPE_N32C);
    if (!conn)
        return -1;

    peer->n32c_state = SEPP_N32C_STATE_CONNECTING;

    SEPP_INFO("started N32-C connection fd %d for peer %s:%u",
              conn->fd,
              peer->n32c_peer_fqdn,
              (unsigned int)peer->n32c_peer_port);
    return 0;
}

static void target_n32f_drain_close_cb(struct sepp_timer *timer, void *arg)
{
    struct sepp_conn *conn = arg;

    (void)timer;

    if (!conn || !conn->ctx ||
        !(conn->flags & SEPP_CONN_F_DRAINING) ||
        (conn->flags & SEPP_CONN_F_DESTROYING))
        return;

    if (!(conn->flags & SEPP_CONN_F_TEARDOWN) &&
        (!sepp_list_empty(&conn->inbound_xacts) ||
         !sepp_list_empty(&conn->outbound_xacts)))
        return;

    SEPP_INFO("closing %s N32-F connection fd %d",
              (conn->flags & SEPP_CONN_F_TEARDOWN) ? "torn-down" : "drained",
              conn->fd);
    sepp_conn_destroy(conn->ctx, conn);
}

int sepp_target_maybe_close_draining_n32f(struct sepp_conn *conn)
{
    if (!conn || !conn->ctx)
        return -1;

    if (!(conn->flags & SEPP_CONN_F_DRAINING) ||
        (conn->flags & SEPP_CONN_F_DESTROYING) ||
        !sepp_list_empty(&conn->inbound_xacts) ||
        !sepp_list_empty(&conn->outbound_xacts) ||
        (sepp_timer_active(&conn->drain_close_timer) &&
         !(conn->flags & SEPP_CONN_F_TEARDOWN)))
        return 0;

    if (sepp_timer_active(&conn->drain_close_timer))
        sepp_timer_stop(conn->ctx, &conn->drain_close_timer);

    if (sepp_timer_start(conn->ctx,
                         &conn->drain_close_timer,
                         1u,
                         target_n32f_drain_close_cb,
                         conn) != 0) {
        SEPP_ERROR("failed to schedule drained N32-F connection fd %d close",
                   conn->fd);
        return -1;
    }

    return 0;
}

int sepp_target_drain_n32f_connections(
    struct sepp_context *ctx,
    const struct sepp_target_key *key)
{
    struct sepp_peer_ctx *peer;
    struct sepp_list *head;
    struct sepp_list *pos;
    struct sepp_list *next;
    unsigned int bucket;
    int rc = 0;

    if (!ctx || !key || key->type != SEPP_TARGET_PEER_SEPP)
        return -1;

    peer = sepp_peer_lookup_target(&ctx->peer_table, key);
    if (!peer)
        return -1;

    /* Release the active and standby slots immediately.  Draining
     * connections remain in the connection table until their streams finish
     * or the bounded teardown timer expires. */
    peer->n32f_conn = NULL;
    peer->n32f_replacement_conn = NULL;

    bucket = sepp_target_hash(key) % SEPP_CONN_TARGET_BUCKETS;
    head = &ctx->conn_table.target_buckets[bucket];

    sepp_list_for_each_safe(pos, next, head) {
        struct sepp_conn *conn;
        uint64_t timeout_ms;

        conn = sepp_list_entry(pos, struct sepp_conn, target_hash_node);
        if (!(conn->flags & SEPP_CONN_F_HAS_TARGET) ||
            conn->type != SEPP_CONN_TYPE_N32F ||
            !sepp_target_equal(&conn->target_key, key) ||
            (conn->flags & SEPP_CONN_F_DESTROYING))
            continue;

        conn->flags |= SEPP_CONN_F_DRAINING | SEPP_CONN_F_TEARDOWN;

        if (sepp_timer_active(&conn->drain_close_timer))
            sepp_timer_stop(ctx, &conn->drain_close_timer);

        if (sepp_list_empty(&conn->inbound_xacts) &&
            sepp_list_empty(&conn->outbound_xacts)) {
            if (sepp_target_maybe_close_draining_n32f(conn) != 0) {
                SEPP_ERROR("failed to schedule N32-F teardown fd %d; closing now",
                           conn->fd);
                sepp_conn_destroy(ctx, conn);
                rc = -1;
            }
            continue;
        }

        timeout_ms = SEPP_N32F_TEARDOWN_DRAIN_TIMEOUT_MS;
        if (sepp_timer_start(ctx,
                             &conn->drain_close_timer,
                             timeout_ms,
                             target_n32f_drain_close_cb,
                             conn) != 0) {
            SEPP_ERROR("failed to schedule N32-F teardown fd %d; closing now",
                       conn->fd);
            sepp_conn_destroy(ctx, conn);
            rc = -1;
        }
    }

    return rc;
}

int sepp_target_start_n32f_replacement(struct sepp_context *ctx,
                                       const struct sepp_target_key *key)
{
    struct sepp_peer_ctx *peer;
    struct sepp_conn *conn;

    if (!ctx || !key || key->type != SEPP_TARGET_PEER_SEPP)
        return -1;

    peer = sepp_peer_lookup_target(&ctx->peer_table, key);
    if (!peer ||
        peer->n32c_state != SEPP_N32C_STATE_ESTABLISHED ||
        peer->selected_security != SEPP_SECURITY_CAPABILITY_TLS ||
        !sepp_target_conn_ready(peer->n32f_conn))
        return -1;

    if (peer->n32f_replacement_conn)
        return 0;

    conn = sepp_connector_connect_n32f_replacement(ctx,
                                                    key,
                                                    peer->n32f_peer_fqdn,
                                                    peer->n32f_peer_port);
    if (!conn)
        return -1;

    SEPP_INFO("started standby N32-F connection fd %d for peer %s:%u",
              conn->fd,
              peer->n32f_peer_fqdn,
              (unsigned int)peer->n32f_peer_port);
    return 0;
}

int sepp_target_n32f_conn_ready(struct sepp_context *ctx,
                                struct sepp_conn *conn)
{
    struct sepp_peer_ctx *peer;
    struct sepp_conn *old;

    if (!ctx || !conn || conn->type != SEPP_CONN_TYPE_N32F ||
        !(conn->flags & SEPP_CONN_F_STANDBY) ||
        !(conn->flags & SEPP_CONN_F_HAS_TARGET))
        return -1;

    peer = sepp_peer_lookup_target(&ctx->peer_table, &conn->target_key);
    if (!peer || peer->n32f_replacement_conn != conn ||
        peer->n32c_state != SEPP_N32C_STATE_ESTABLISHED ||
        peer->selected_security != SEPP_SECURITY_CAPABILITY_TLS)
        return -1;

    old = peer->n32f_conn;
    if (old)
        old->flags |= SEPP_CONN_F_DRAINING;

    conn->flags &= ~SEPP_CONN_F_STANDBY;
    peer->n32f_replacement_conn = NULL;
    peer->n32f_conn = conn;

    SEPP_INFO("promoted standby N32-F connection fd %d for peer %s; old fd %d draining",
              conn->fd,
              peer->target.fqdn,
              old ? old->fd : -1);

    if (old)
        (void)sepp_target_maybe_close_draining_n32f(old);

    return 0;
}

void sepp_target_get_status(struct sepp_context *ctx,
                            const struct sepp_target_key *key,
                            const struct sepp_target_config *cfg,
                            struct sepp_conn *conn,
                            struct sepp_target_status_info *info)
{
    if (!info)
        return;

    target_status_set(info, SEPP_TARGET_STATUS_FAILED, conn, NULL);

    if (!ctx || !key || key->type == SEPP_TARGET_NONE)
        return;

    if (cfg && cfg->type != key->type)
        return;

    switch (key->type) {
    case SEPP_TARGET_PEER_SEPP:
        target_peer_status(ctx, key, conn, info);
        break;
    case SEPP_TARGET_INTERNAL_NF:
    case SEPP_TARGET_SCP:
        target_plain_status(conn, info);
        break;
    case SEPP_TARGET_NONE:
    default:
        target_status_set(info, SEPP_TARGET_STATUS_FAILED, conn, NULL);
        break;
    }
}
