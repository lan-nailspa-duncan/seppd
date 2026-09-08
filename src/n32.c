#include "connection.h"
#include "http2.h"
#include "log.h"
#include "n32.h"
#include "n32c.h"
#include "n32f.h"
#include "peer.h"
#include "sbi.h"
#include "sepp.h"
#include "sepp_msg.h"
#include "tls_channel.h"

#define N32_CONTEXT_NOT_FOUND_DETAIL \
    "No established N32-C context matches the TLS peer identity"

enum n32_peer_match_result {
    N32_PEER_MATCH_NONE = 0,
    N32_PEER_MATCH_CERTIFICATE,
    N32_PEER_MATCH_VIA,
    N32_PEER_MATCH_AMBIGUOUS,
};

static int n32_peer_has_established_tls_context(
    const struct sepp_peer_ctx *peer)
{
    return peer &&
           peer->n32c_state == SEPP_N32C_STATE_ESTABLISHED &&
           peer->selected_security == SEPP_SECURITY_CAPABILITY_TLS;
}

static int n32_peer_certificate_matches_context(
    const struct sepp_conn *conn,
    const struct sepp_peer_ctx *peer)
{
    if (!conn || !peer || peer->sender_fqdn[0] == '\0')
        return 0;

    if (sepp_tls_peer_matches_hostname(conn, peer->sender_fqdn) == 1)
        return 1;

    return peer->sender_n32f_fqdn[0] != '\0' &&
           sepp_tls_peer_matches_hostname(conn,
                                          peer->sender_n32f_fqdn) == 1;
}

static int n32_peer_via_matches_context(const struct sepp_msg *msg,
                                        const struct sepp_peer_ctx *peer)
{
    if (!msg || !peer || peer->sender_fqdn[0] == '\0')
        return 0;

    if (sepp_sbi_via_has_sepp_fqdn(msg->headers,
                                   msg->header_count,
                                   peer->sender_fqdn))
        return 1;

    return peer->sender_n32f_fqdn[0] != '\0' &&
           sepp_sbi_via_has_sepp_fqdn(msg->headers,
                                      msg->header_count,
                                      peer->sender_n32f_fqdn);
}

static struct sepp_peer_ctx *n32_find_inbound_n32f_peer(
    struct sepp_context *ctx,
    const struct sepp_msg *msg,
    enum n32_peer_match_result *result)
{
    struct sepp_peer_ctx *cert_match = NULL;
    struct sepp_peer_ctx *via_match = NULL;
    unsigned int cert_match_count = 0;
    unsigned int via_match_count = 0;

    if (!ctx || !msg || !msg->conn || !result)
        return NULL;

    *result = N32_PEER_MATCH_NONE;

    for (unsigned int i = 0; i < SEPP_PEER_BUCKETS; i++) {
        struct sepp_list *pos;

        sepp_list_for_each(pos, &ctx->peer_table.buckets[i]) {
            struct sepp_peer_ctx *peer;

            peer = sepp_list_entry(pos, struct sepp_peer_ctx, hash_node);
            if (!n32_peer_has_established_tls_context(peer))
                continue;

            if (!n32_peer_certificate_matches_context(msg->conn, peer))
                continue;

            cert_match = peer;
            cert_match_count++;

            /* Via is only a disambiguator among peers already authorized by
             * the TLS certificate.  It never introduces a new candidate. */
            if (n32_peer_via_matches_context(msg, peer)) {
                via_match = peer;
                via_match_count++;
            }
        }
    }

    if (cert_match_count == 0)
        return NULL;

    if (cert_match_count == 1) {
        *result = N32_PEER_MATCH_CERTIFICATE;
        return cert_match;
    }

    if (via_match_count == 1) {
        *result = N32_PEER_MATCH_VIA;
        return via_match;
    }

    *result = N32_PEER_MATCH_AMBIGUOUS;
    return NULL;
}

static struct sepp_peer_ctx *n32_bound_inbound_n32f_peer(
    struct sepp_context *ctx,
    const struct sepp_conn *conn)
{
    struct sepp_peer_ctx *peer;

    if (!ctx || !conn || !(conn->flags & SEPP_CONN_F_HAS_TARGET))
        return NULL;

    peer = sepp_peer_lookup_target(&ctx->peer_table, &conn->target_key);
    if (!n32_peer_has_established_tls_context(peer))
        return NULL;

    if (!n32_peer_certificate_matches_context(conn, peer))
        return NULL;

    return peer;
}

static int n32_send_context_not_found(const struct sepp_msg *msg)
{
    static const char body[] =
        "{\"status\":403,\"cause\":\"CONTEXT_NOT_FOUND\","
        "\"detail\":\"" N32_CONTEXT_NOT_FOUND_DETAIL "\"}";

    if (!msg || !msg->conn || msg->type != SEPP_MSG_TYPE_REQUEST)
        return -1;

    return sepp_http2_submit_response(msg->conn,
                                      msg->stream_id,
                                      403,
                                      "application/problem+json",
                                      NULL,
                                      NULL,
                                      NULL,
                                      0,
                                      (const unsigned char *)body,
                                      sizeof(body) - 1u);
}

/*
 * Correlate an inbound N32-F request with the single established N32-C peer
 * context selected by the TLS client certificate.  Return 1 when the request
 * may be dispatched, 0 when a 403 response was submitted, and -1 on a local
 * error.
 */
static int n32_correlate_inbound_n32f(struct sepp_context *ctx,
                                     const struct sepp_msg *msg)
{
    struct sepp_conn *conn;
    struct sepp_peer_ctx *peer;
    enum n32_peer_match_result match_result;

    if (!ctx || !msg || !msg->conn ||
        msg->type != SEPP_MSG_TYPE_REQUEST)
        return -1;

    conn = msg->conn;
    if ((conn->flags & SEPP_CONN_F_OUTBOUND) ||
        !(conn->flags & SEPP_CONN_F_TLS_SERVER))
        return 1;

    if (conn->flags & SEPP_CONN_F_HAS_TARGET) {
        /* The first request already performed full certificate/Via
         * correlation.  Use the bound target for the hot path. */
        peer = n32_bound_inbound_n32f_peer(ctx, conn);
        match_result = N32_PEER_MATCH_NONE;
        if (peer)
            match_result = N32_PEER_MATCH_CERTIFICATE;
    } else {
        peer = n32_find_inbound_n32f_peer(ctx, msg, &match_result);
    }

    if (!peer) {
        const char *reason;

        if (match_result == N32_PEER_MATCH_AMBIGUOUS)
            reason = "certificate match is ambiguous and Via does not select one peer";
        else
            reason = "no established N32-C context matches the TLS peer";

        SEPP_INFO("rejecting inbound N32-F request fd %d stream %d: %s",
                  conn->fd,
                  msg->stream_id,
                  reason);
        return n32_send_context_not_found(msg);
    }

    if (!(conn->flags & SEPP_CONN_F_HAS_TARGET)) {
        /* Keep UNKNOWN while inserting the inbound connection so it can
         * coexist with a locally initiated N32-F connection to this peer. */
        if (sepp_conn_set_target(&ctx->conn_table, conn, &peer->target) != 0)
            return -1;
        sepp_conn_set_type(conn, SEPP_CONN_TYPE_N32F);

        SEPP_INFO("correlated inbound N32-F connection fd %d with peer %s using %s",
                  conn->fd,
                  peer->target.fqdn,
                  match_result == N32_PEER_MATCH_VIA ? "Via" : "certificate");
    }

    return 1;
}

const char *sepp_n32_operation_name(enum sepp_n32_operation op)
{
    switch (op) {
    case SEPP_N32C_OP_EXCHANGE_CAPABILITY:
        return "n32c.exchange-capability";
    case SEPP_N32C_OP_N32F_TERMINATE:
        return "n32c.n32f-terminate";
    case SEPP_N32C_OP_N32F_ERROR:
        return "n32c.n32f-error";
    case SEPP_N32F_OP_NSMF_PDUSESSION:
        return "n32f.nsmf-pdusession";
    case SEPP_N32_OP_UNKNOWN:
    default:
        return "unknown";
    }
}

static int n32_msg_handler(struct sepp_context *ctx,
                           const struct sepp_msg *msg,
                           void *arg)
{
    (void)arg;

    if (!ctx || !msg || !msg->conn)
        return -1;

    switch (msg->conn->type) {
    case SEPP_CONN_TYPE_N32C:
        return sepp_n32c_handle_msg(ctx, msg);
    case SEPP_CONN_TYPE_N32F:
        if (msg->type == SEPP_MSG_TYPE_REQUEST &&
            !(msg->conn->flags & SEPP_CONN_F_OUTBOUND)) {
            int rc = n32_correlate_inbound_n32f(ctx, msg);

            if (rc <= 0)
                return rc;
        }
        return sepp_n32f_handle_msg(ctx, msg);
    case SEPP_CONN_TYPE_INTERNAL_NF:
    case SEPP_CONN_TYPE_SCP:
        return sepp_n32f_handle_msg(ctx, msg);
    case SEPP_CONN_TYPE_UNKNOWN:
        if (msg->type == SEPP_MSG_TYPE_REQUEST &&
            sepp_n32c_path_matches(msg->path)) {
            sepp_conn_set_type(msg->conn, SEPP_CONN_TYPE_N32C);
            return sepp_n32c_handle_msg(ctx, msg);
        }

        if (msg->type == SEPP_MSG_TYPE_REQUEST) {
            int rc = n32_correlate_inbound_n32f(ctx, msg);

            if (rc <= 0)
                return rc;

            return sepp_n32f_handle_msg(ctx, msg);
        }

        SEPP_INFO("SEPP message on unclassified connection fd %d stream %d",
                  msg->conn->fd,
                  msg->stream_id);
        return 0;
    default:
        SEPP_ERROR("SEPP message on unsupported connection type %s fd %d stream %d",
                   sepp_conn_type_name(msg->conn->type),
                   msg->conn->fd,
                   msg->stream_id);
        return -1;
    }
}

int sepp_n32_init(struct sepp_context *ctx)
{
    if (!ctx)
        return -1;

    sepp_msg_set_handler(&ctx->msg_dispatcher, n32_msg_handler, NULL);
    SEPP_INFO("N32 dispatcher initialized");

    return 0;
}

void sepp_n32_cleanup(struct sepp_context *ctx)
{
    if (!ctx)
        return;

    sepp_msg_set_handler(&ctx->msg_dispatcher, NULL, NULL);
}
