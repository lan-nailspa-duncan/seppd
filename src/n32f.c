#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "config.h"
#include "connection.h"
#include "connector.h"
#include "http2.h"
#include "log.h"
#include "n32.h"
#include "n32f.h"
#include "routing.h"
#include "sepp.h"
#include "sepp_msg.h"
#include "stream.h"
#include "target.h"
#include "target_manager.h"

#define N32F_NSMF_PDUSESSION_PREFIX "/nsmf-pdusession/v1/pdu-sessions"
#define N32F_LOCAL_VIA_MAX (SEPP_CONFIG_FQDN_LEN + sizeof("2.0 SEPP-"))

static enum sepp_n32_operation n32f_operation_from_request(const struct sepp_msg *msg)
{
    size_t len = sizeof(N32F_NSMF_PDUSESSION_PREFIX) - 1u;

    if (!msg || msg->path[0] == '\0')
        return SEPP_N32_OP_UNKNOWN;

    if (strncmp(msg->path, N32F_NSMF_PDUSESSION_PREFIX, len) == 0)
        return SEPP_N32F_OP_NSMF_PDUSESSION;

    return SEPP_N32_OP_UNKNOWN;
}

static enum sepp_conn_type n32f_conn_type_from_target(const struct sepp_target_config *cfg)
{
    if (!cfg)
        return SEPP_CONN_TYPE_UNKNOWN;

    switch (cfg->type) {
    case SEPP_TARGET_PEER_SEPP:
        return SEPP_CONN_TYPE_N32F;
    case SEPP_TARGET_SCP:
        return SEPP_CONN_TYPE_SCP;
    case SEPP_TARGET_INTERNAL_NF:
        return SEPP_CONN_TYPE_INTERNAL_NF;
    case SEPP_TARGET_NONE:
    default:
        return SEPP_CONN_TYPE_UNKNOWN;
    }
}

static const char *n32f_find_header(const struct sepp_msg *msg, const char *name)
{
    size_t i;

    if (!msg || !name)
        return NULL;

    for (i = 0; i < msg->header_count; i++) {
        if (!msg->headers[i].name)
            continue;

        if (strcmp(msg->headers[i].name, name) == 0)
            return msg->headers[i].value;
    }

    return NULL;
}

static const char *n32f_content_type(const struct sepp_msg *msg)
{
    const char *content_type;

    content_type = n32f_find_header(msg, "content-type");
    return content_type ? content_type : "application/json";
}

static int n32f_format_local_via(const struct sepp_context *ctx,
                                 char *via,
                                 size_t via_len)
{
    int len;

    if (!ctx || !via || via_len == 0 ||
        ctx->config.local_fqdn[0] == '\0')
        return -1;

    len = snprintf(via,
                   via_len,
                   "2.0 SEPP-%s",
                   ctx->config.local_fqdn);
    if (len < 0 || (size_t)len >= via_len)
        return -1;

    return 0;
}

static void n32f_format_authority(char *authority,
                                  size_t authority_len,
                                  const struct sepp_target_key *target,
                                  uint16_t port)
{
    if (!authority || authority_len == 0)
        return;

    authority[0] = '\0';

    if (!target)
        return;

    if (port == 443)
        snprintf(authority, authority_len, "%s", target->fqdn);
    else
        snprintf(authority,
                 authority_len,
                 "%s:%u",
                 target->fqdn,
                 (unsigned int)port);
}

static int n32f_api_root_from_request_uri(const struct sepp_msg *msg,
                                          char *api_root,
                                          size_t api_root_len)
{
    int len;

    if (!msg || !api_root || api_root_len == 0 ||
        strcasecmp(msg->scheme, "https") != 0 ||
        msg->authority[0] == '\0' ||
        strpbrk(msg->authority, "/?#@") != NULL)
        return -1;

    len = snprintf(api_root, api_root_len, "https://%s", msg->authority);
    if (len < 0 || (size_t)len >= api_root_len)
        return -1;

    return 0;
}

static int n32f_authority_from_api_root(const char *api_root,
                                        char *authority,
                                        size_t authority_len)
{
    struct sepp_target_key target;
    uint16_t port;

    memset(&target, 0, sizeof(target));
    if (sepp_routing_parse_api_root(api_root,
                                    target.fqdn,
                                    sizeof(target.fqdn),
                                    &port) != 0)
        return -1;

    n32f_format_authority(authority, authority_len, &target, port);
    return authority[0] == '\0' ? -1 : 0;
}

static int n32f_send_error_response(const struct sepp_msg *msg,
                                    unsigned int status,
                                    const char *reason)
{
    char body[256];
    int len;

    if (!msg || !msg->conn || msg->type != SEPP_MSG_TYPE_REQUEST)
        return -1;

    len = snprintf(body,
                   sizeof(body),
                   "{\"error\":\"%s\"}",
                   reason ? reason : "n32f forwarding error");
    if (len < 0)
        return -1;

    return sepp_http2_submit_response(msg->conn,
                                      msg->stream_id,
                                      status,
                                      "application/json",
                                      NULL,
                                      NULL,
                                      NULL,
                                      0,
                                      (const unsigned char *)body,
                                      (size_t)len);
}

static int n32f_send_loop_response(const struct sepp_msg *msg)
{
    static const unsigned char body[] =
        "{\"status\":400,\"cause\":\"MSG_LOOP_DETECTED\","
        "\"detail\":\"local SEPP is already present in Via\"}";

    if (!msg || !msg->conn || msg->type != SEPP_MSG_TYPE_REQUEST)
        return -1;

    return sepp_http2_submit_response(msg->conn,
                                      msg->stream_id,
                                      400,
                                      "application/problem+json",
                                      NULL,
                                      NULL,
                                      NULL,
                                      0,
                                      body,
                                      sizeof(body) - 1u);
}

static int n32f_forward_request(struct sepp_context *ctx,
                                const struct sepp_msg *msg,
                                enum sepp_n32_operation op)
{
    const struct sepp_target_config *target_cfg = NULL;
    struct sepp_target_key target;
    struct sepp_conn *out_conn;
    char authority[SEPP_TARGET_FQDN_MAX + 16u];
    char effective_api_root[SEPP_SBI_TARGET_API_ROOT_MAX];
    char local_via[N32F_LOCAL_VIA_MAX];
    const char *forwarded_target_api_root = NULL;
    int preserve_target_api_root = 0;
    int inbound_n32f;
    int peer_uses_target_api_root = 0;
    int32_t out_stream_id;

    if (!ctx || !msg || !msg->conn)
        return -1;

    if (n32f_format_local_via(ctx, local_via, sizeof(local_via)) != 0)
        return n32f_send_error_response(msg, 500, "local SEPP FQDN is unavailable");

    if (sepp_sbi_via_has_sepp_fqdn(msg->headers,
                                   msg->header_count,
                                   ctx->config.local_fqdn)) {
        SEPP_INFO("rejecting N32-F request fd %d stream %d: local SEPP is already present in Via",
                  msg->conn->fd,
                  msg->stream_id);
        return n32f_send_loop_response(msg);
    }

    inbound_n32f = msg->conn->type == SEPP_CONN_TYPE_N32F &&
                   !(msg->conn->flags & SEPP_CONN_F_OUTBOUND);
    effective_api_root[0] = '\0';

    if (inbound_n32f) {
        struct sepp_peer_ctx *peer;

        if (!(msg->conn->flags & SEPP_CONN_F_HAS_TARGET))
            return n32f_send_error_response(msg, 403, "N32-F peer is not correlated");
        peer = sepp_peer_lookup_target(&ctx->peer_table,
                                       &msg->conn->target_key);
        if (!peer)
            return n32f_send_error_response(msg, 403, "N32-F peer context unavailable");

        peer_uses_target_api_root =
            !!(peer->negotiated_features & SEPP_PEER_F_TARGET_API_ROOT);
        if (peer_uses_target_api_root) {
            if (msg->sbi.target_api_root[0] == '\0')
                return n32f_send_error_response(
                    msg, 400, "missing negotiated 3gpp-Sbi-Target-apiRoot");
            snprintf(effective_api_root,
                     sizeof(effective_api_root),
                     "%s",
                     msg->sbi.target_api_root);
        } else {
            if (msg->sbi.target_api_root[0] != '\0')
                return n32f_send_error_response(
                    msg, 400, "3gpp-Sbi-Target-apiRoot was not negotiated");
            if (n32f_api_root_from_request_uri(msg,
                                               effective_api_root,
                                               sizeof(effective_api_root)) != 0)
                return n32f_send_error_response(
                    msg, 400, "invalid headerless N32-F target URI");
        }

        if (sepp_routing_internal_from_api_root(ctx,
                                                effective_api_root,
                                                &target,
                                                &target_cfg,
                                                &preserve_target_api_root) != 0)
            return n32f_send_error_response(msg, 502, "local target apiRoot is not routable");
    } else {
        if (msg->sbi.target_api_root[0] == '\0')
            return n32f_send_error_response(
                msg, 400, "missing 3gpp-Sbi-Target-apiRoot");
        snprintf(effective_api_root,
                 sizeof(effective_api_root),
                 "%s",
                 msg->sbi.target_api_root);
        if (sepp_routing_peer_from_api_root(ctx,
                                            effective_api_root,
                                            &target,
                                            &target_cfg) != 0)
            return n32f_send_error_response(msg, 502, "no peer route for target apiRoot");
    }

    if (!target_cfg)
        return n32f_send_error_response(msg, 502, "target apiRoot is not routable");

    {
        struct sepp_target_status_info status;

        sepp_target_get_status(ctx, &target, target_cfg, NULL, &status);
        if (status.status == SEPP_TARGET_STATUS_NEEDS_N32C) {
            if (sepp_target_start_n32c(ctx, &target) != 0) {
                SEPP_ERROR("failed to start N32-C setup for target %s:%u",
                           target.fqdn,
                           (unsigned int)target_cfg->port);
            } else {
                SEPP_INFO("N32-C setup started for target %s:%u",
                          target.fqdn,
                          (unsigned int)target_cfg->port);
            }

            return n32f_send_error_response(msg, 503, "target requires N32-C setup");
        }

        if (status.status == SEPP_TARGET_STATUS_FAILED)
            return n32f_send_error_response(msg, 503, "target is not available");
    }

    if (target.type == SEPP_TARGET_PEER_SEPP) {
        struct sepp_peer_ctx *peer;

        peer = sepp_peer_lookup_target(&ctx->peer_table, &target);
        if (!peer)
            return n32f_send_error_response(msg, 503, "peer context unavailable");
        peer_uses_target_api_root =
            !!(peer->negotiated_features & SEPP_PEER_F_TARGET_API_ROOT);
        out_conn = sepp_connector_get_or_connect_type(
            ctx, &target, peer->n32f_peer_fqdn, peer->n32f_peer_port,
            n32f_conn_type_from_target(target_cfg));
    } else {
        out_conn = sepp_connector_get_or_connect_type(
            ctx, &target, target.fqdn, target_cfg->port,
            n32f_conn_type_from_target(target_cfg));
    }
    if (!out_conn)
        return n32f_send_error_response(msg, 503, "target connection unavailable");

    {
        struct sepp_target_status_info status;

        sepp_target_get_status(ctx, &target, target_cfg, out_conn, &status);
        if (status.status != SEPP_TARGET_STATUS_READY) {
            SEPP_ERROR("N32-F target %s:%u is not ready: %s",
                       target.fqdn,
                       (unsigned int)target_cfg->port,
                       sepp_target_status_name(status.status));
            return n32f_send_error_response(msg, 503, "target is not ready");
        }

        out_conn = status.conn;
    }

    if (target.type == SEPP_TARGET_PEER_SEPP &&
        peer_uses_target_api_root) {
        struct sepp_peer_ctx *peer =
            sepp_peer_lookup_target(&ctx->peer_table, &target);
        struct sepp_target_key wire_target = target;

        if (!peer)
            return n32f_send_error_response(msg, 503, "peer context unavailable");
        snprintf(wire_target.fqdn,
                 sizeof(wire_target.fqdn),
                 "%s",
                 peer->n32f_peer_fqdn);
        n32f_format_authority(authority,
                              sizeof(authority),
                              &wire_target,
                              peer->n32f_peer_port);
    } else if (target.type == SEPP_TARGET_PEER_SEPP) {
        if (n32f_authority_from_api_root(effective_api_root,
                                         authority,
                                         sizeof(authority)) != 0)
            return n32f_send_error_response(
                msg, 400, "invalid target apiRoot for headerless N32-F");
    } else {
        n32f_format_authority(authority,
                              sizeof(authority),
                              &target,
                              target_cfg->port);
    }

    if ((target.type == SEPP_TARGET_PEER_SEPP &&
         peer_uses_target_api_root) ||
        (target.type != SEPP_TARGET_PEER_SEPP &&
         preserve_target_api_root))
        forwarded_target_api_root = effective_api_root;

    if (target.type == SEPP_TARGET_PEER_SEPP &&
        sepp_http2_needs_rotation(out_conn) &&
        sepp_target_start_n32f_replacement(ctx, &target) != 0) {
        SEPP_ERROR("failed to start N32-F stream-ID rotation for %s:%u",
                   target.fqdn,
                   (unsigned int)target_cfg->port);
    }

    out_stream_id = sepp_http2_submit_request(out_conn,
                                              msg->method,
                                              msg->scheme[0] ? msg->scheme : "https",
                                              authority,
                                              msg->path,
                                              n32f_content_type(msg),
                                              forwarded_target_api_root,
                                              n32f_find_header(msg, "content-encoding"),
                                              local_via,
                                              msg->headers,
                                              msg->header_count,
                                              msg->body,
                                              msg->body_len);
    if (out_stream_id <= 0)
        return n32f_send_error_response(msg, 503, "target HTTP/2 session unavailable");

    if (!sepp_stream_create(ctx,
                            msg->conn,
                            msg->stream_id,
                            out_conn,
                            out_stream_id))
        return n32f_send_error_response(msg, 500, "stream mapping failed");

    SEPP_INFO("N32-F forward request in fd %d stream %d -> out fd %d stream %d target=%s:%u op=%s",
              msg->conn->fd,
              msg->stream_id,
              out_conn->fd,
              out_stream_id,
              target.fqdn,
              (unsigned int)target_cfg->port,
              sepp_n32_operation_name(op));

    return 0;
}

static int n32f_forward_response(struct sepp_context *ctx,
                                 const struct sepp_msg *msg)
{
    struct sepp_stream_xact *xact;
    char local_via[N32F_LOCAL_VIA_MAX];
    int rc;

    if (!ctx || !msg || !msg->conn)
        return -1;

    if (n32f_format_local_via(ctx, local_via, sizeof(local_via)) != 0)
        return -1;

    xact = sepp_stream_lookup_out(&ctx->stream_table, msg->conn, msg->stream_id);
    if (!xact) {
        SEPP_INFO("N32-F response stub fd %d stream %d status=%u without forwarding mapping",
                  msg->conn->fd,
                  msg->stream_id,
                  msg->status);
        return 0;
    }

    rc = sepp_http2_submit_response(xact->in_conn,
                                    xact->in_stream_id,
                                    msg->status,
                                    n32f_content_type(msg),
                                    n32f_find_header(msg, "content-encoding"),
                                    local_via,
                                    msg->headers,
                                    msg->header_count,
                                    msg->body,
                                    msg->body_len);
    if (rc == 0) {
        SEPP_INFO("N32-F forward response out fd %d stream %d -> in fd %d stream %d status=%u",
                  msg->conn->fd,
                  msg->stream_id,
                  xact->in_conn->fd,
                  xact->in_stream_id,
                  msg->status);
        sepp_stream_destroy(ctx, xact);
    }

    return rc;
}

int sepp_n32f_handle_msg(struct sepp_context *ctx,
                         const struct sepp_msg *msg)
{
    enum sepp_n32_operation op;

    if (!msg || !msg->conn)
        return -1;

    if (msg->type == SEPP_MSG_TYPE_REQUEST) {
        op = n32f_operation_from_request(msg);
        if (msg->stream)
            sepp_http2_stream_set_n32_operation(msg->stream, op);

        SEPP_INFO("N32-F request fd %d stream %d op=%s method=%s path=%s body=%zu",
                  msg->conn->fd,
                  msg->stream_id,
                  sepp_n32_operation_name(op),
                  msg->method,
                  msg->path,
                  msg->body_len);

        return n32f_forward_request(ctx, msg, op);
    }

    if (msg->type == SEPP_MSG_TYPE_RESPONSE) {
        op = msg->n32_operation;
        SEPP_INFO("N32-F response fd %d stream %d op=%s status=%u",
                  msg->conn->fd,
                  msg->stream_id,
                  sepp_n32_operation_name(op),
                  msg->status);
        return n32f_forward_response(ctx, msg);
    }

    SEPP_ERROR("unsupported N32-F message type %d on fd %d stream %d",
               msg->type,
               msg->conn->fd,
               msg->stream_id);
    return -1;
}
