#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include <cjson/cJSON.h>

#include "connection.h"
#include "connector.h"
#include "http2.h"
#include "log.h"
#include "n32.h"
#include "n32c.h"
#include "peer.h"
#include "sepp.h"
#include "sepp_msg.h"
#include "target_manager.h"
#include "timer.h"

#define N32C_PATH_PREFIX "/n32c-handshake/v1"
#define N32C_EXCHANGE_CAPABILITY_PATH "/n32c-handshake/v1/exchange-capability"
#define N32C_N32F_TERMINATE_PATH      "/n32c-handshake/v1/n32f-terminate"
#define N32C_N32F_ERROR_PATH          "/n32c-handshake/v1/n32f-error"

/* Feature number 1 (NFTLST) is the least-significant bit. */
#define N32C_SUPPORTED_FEATURES "1"

static void n32c_redirect_timer_cb(struct sepp_timer *timer, void *arg);

static const char *n32c_find_header(const struct sepp_msg *msg,
                                    const char *name)
{
    size_t i;

    if (!msg || !name)
        return NULL;
    for (i = 0; i < msg->header_count; i++) {
        if (msg->headers[i].name && msg->headers[i].value &&
            strcasecmp(msg->headers[i].name, name) == 0)
            return msg->headers[i].value;
    }
    return NULL;
}

/* Accept only an absolute HTTPS URI with an FQDN, optional numeric port, and
 * the exchange-capability path.  Userinfo, query strings, fragments, IP
 * literals and cross-operation redirects are deliberately rejected. */
static int n32c_parse_redirect_uri(const char *uri,
                                   char *host, size_t host_len,
                                   uint16_t *port,
                                   char *path, size_t path_len)
{
    const char *authority;
    const char *slash;
    const char *colon;
    size_t authority_len;
    size_t name_len;
    unsigned long parsed_port = 443;
    char *end;

    if (!uri || !host || !port || !path ||
        strncmp(uri, "https://", 8u) != 0)
        return -1;
    authority = uri + 8u;
    slash = strchr(authority, '/');
    if (!slash || strchr(authority, '@') || strchr(slash, '?') ||
        strchr(slash, '#') || strcmp(slash, N32C_EXCHANGE_CAPABILITY_PATH) != 0)
        return -1;
    authority_len = (size_t)(slash - authority);
    if (authority_len == 0 || authority_len >= SEPP_TARGET_FQDN_MAX ||
        memchr(authority, '[', authority_len) ||
        memchr(authority, ']', authority_len))
        return -1;

    colon = memchr(authority, ':', authority_len);
    name_len = colon ? (size_t)(colon - authority) : authority_len;
    if (name_len == 0 || name_len >= host_len ||
        !memchr(authority, '.', name_len))
        return -1;
    if (colon) {
        if (memchr(colon + 1, ':', authority_len - name_len - 1u))
            return -1;
        parsed_port = strtoul(colon + 1, &end, 10);
        if (end != authority + authority_len || parsed_port == 0 ||
            parsed_port > 65535ul)
            return -1;
    }
    memcpy(host, authority, name_len);
    host[name_len] = '\0';
    if (snprintf(path, path_len, "%s", slash) >= (int)path_len)
        return -1;
    *port = (uint16_t)parsed_port;
    return 0;
}

static int n32c_path_matches(const char *path)
{
    size_t len = sizeof(N32C_PATH_PREFIX) - 1u;

    if (!path)
        return 0;

    if (strncmp(path, N32C_PATH_PREFIX, len) != 0)
        return 0;

    return path[len] == '\0' || path[len] == '/';
}

int sepp_n32c_path_matches(const char *path)
{
    return n32c_path_matches(path);
}

static enum sepp_n32_operation n32c_operation_from_request(const char *path)
{
    if (!path)
        return SEPP_N32_OP_UNKNOWN;

    if (strcmp(path, N32C_EXCHANGE_CAPABILITY_PATH) == 0)
        return SEPP_N32C_OP_EXCHANGE_CAPABILITY;

    if (strcmp(path, N32C_N32F_TERMINATE_PATH) == 0)
        return SEPP_N32C_OP_N32F_TERMINATE;

    if (strcmp(path, N32C_N32F_ERROR_PATH) == 0)
        return SEPP_N32C_OP_N32F_ERROR;

    return SEPP_N32_OP_UNKNOWN;
}

static int n32c_send_json_response(const struct sepp_msg *msg,
                                   unsigned int status,
                                   const char *body)
{
    if (!msg || !msg->conn || !body)
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
                                      strlen(body));
}

static int n32c_json_array_has_string(const cJSON *array, const char *value)
{
    const cJSON *item;

    if (!cJSON_IsArray(array) || !value)
        return 0;

    cJSON_ArrayForEach(item, array) {
        if (cJSON_IsString(item) && item->valuestring &&
            strcmp(item->valuestring, value) == 0)
            return 1;
    }

    return 0;
}

static int n32c_json_array_is_single_string(const cJSON *array,
                                             const char *value)
{
    const cJSON *item;

    if (!cJSON_IsArray(array) || !value || cJSON_GetArraySize(array) != 1)
        return 0;

    item = cJSON_GetArrayItem(array, 0);
    return cJSON_IsString(item) && item->valuestring &&
           strcmp(item->valuestring, value) == 0;
}

static int n32c_hex_value(char ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    return -1;
}

static int n32c_parse_supported_features(const cJSON *item, int *nftlst)
{
    const char *value;
    size_t len;

    if (!nftlst)
        return 0;

    *nftlst = 0;
    if (!item)
        return 1;

    if (!cJSON_IsString(item) || !item->valuestring)
        return 0;

    value = item->valuestring;
    len = strlen(value);
    if (len == 0)
        return 0;

    for (size_t i = 0; i < len; i++) {
        if (n32c_hex_value(value[i]) < 0)
            return 0;
    }

    *nftlst = (n32c_hex_value(value[len - 1u]) & 1) != 0;
    return 1;
}

static int n32c_fqdn_ie_valid(const cJSON *item, int required)
{
    size_t len;

    if (!item)
        return !required;

    if (!cJSON_IsString(item) || !item->valuestring)
        return 0;

    len = strlen(item->valuestring);
    return len > 0 && len < SEPP_TARGET_FQDN_MAX;
}

static void n32c_store_peer_identity(struct sepp_peer_ctx *peer,
                                     const cJSON *sender,
                                     const cJSON *sender_n32f_fqdn)
{
    if (!peer || !sender || !sender->valuestring)
        return;

    snprintf(peer->sender_fqdn,
             sizeof(peer->sender_fqdn),
             "%s",
             sender->valuestring);

    peer->sender_n32f_fqdn[0] = '\0';
    if (sender_n32f_fqdn && sender_n32f_fqdn->valuestring) {
        snprintf(peer->sender_n32f_fqdn,
                 sizeof(peer->sender_n32f_fqdn),
                 "%s",
                 sender_n32f_fqdn->valuestring);
    }
}

static struct sepp_peer_ctx *n32c_peer_for_outbound_conn(
    struct sepp_context *ctx,
    const struct sepp_conn *conn)
{
    if (!ctx || !conn || !(conn->flags & SEPP_CONN_F_HAS_TARGET))
        return NULL;

    return sepp_peer_lookup_target(&ctx->peer_table, &conn->target_key);
}

static int n32c_bind_inbound_peer(struct sepp_context *ctx,
                                  struct sepp_conn *conn,
                                  const char *sender,
                                  struct sepp_peer_ctx **peer_out)
{
    struct sepp_peer_ctx *peer;

    if (!ctx || !conn || !sender || !peer_out)
        return -1;

    peer = sepp_peer_lookup_fqdn(&ctx->peer_table, sender);
    if (!peer)
        peer = sepp_peer_lookup_learned_fqdn(&ctx->peer_table, sender);
    if (!peer)
        return -1;

    if (conn->flags & SEPP_CONN_F_HAS_TARGET) {
        if (!sepp_target_equal(&conn->target_key, &peer->target))
            return -1;
    } else {
        if (sepp_conn_set_target(&ctx->conn_table, conn, &peer->target) != 0)
            return -1;
    }

    sepp_conn_set_type(conn, SEPP_CONN_TYPE_N32C);

    /* Inbound and outbound N32-C connections may coexist.  The peer's
     * n32c_conn slot tracks the locally initiated connection only. */
    *peer_out = peer;
    return 0;
}

/* Splits local_plmn ("<3-digit mcc><2-or-3-digit mnc>", e.g. "99970")
 * into a one-element plmnIdList array and attaches it to root. Peers use
 * this to learn which PLMN(s) we serve via sepp_node_find_by_plmn_id()-
 * style lookups derived purely from the N32-C handshake body, with no
 * NRF involvement on their side. Returns 0 on success (including when
 * local_plmn is unset, in which case nothing is added), -1 on failure. */
static int n32c_add_local_plmn_list(const struct sepp_context *ctx,
                                    cJSON *root)
{
    cJSON *plmn_list;
    cJSON *plmn_entry;
    char mcc[4];
    const char *mnc;
    size_t len;

    if (!ctx || !root)
        return -1;

    len = strlen(ctx->config.local_plmn);
    if (len < 5 || len > 6)
        return 0;

    memcpy(mcc, ctx->config.local_plmn, 3);
    mcc[3] = '\0';
    mnc = ctx->config.local_plmn + 3;

    plmn_list = cJSON_CreateArray();
    plmn_entry = cJSON_CreateObject();
    if (!plmn_list || !plmn_entry) {
        cJSON_Delete(plmn_list);
        cJSON_Delete(plmn_entry);
        return -1;
    }

    if (!cJSON_AddStringToObject(plmn_entry, "mcc", mcc) ||
        !cJSON_AddStringToObject(plmn_entry, "mnc", mnc) ||
        !cJSON_AddItemToArray(plmn_list, plmn_entry)) {
        cJSON_Delete(plmn_list);
        cJSON_Delete(plmn_entry);
        return -1;
    }

    cJSON_AddItemToObject(root, "plmnIdList", plmn_list);
    return 0;
}

static char *n32c_build_capability_request(const struct sepp_context *ctx,
                                           const char *capability)
{
    cJSON *root;
    cJSON *caps;
    char *body;

    if (!ctx || !capability || ctx->config.local_fqdn[0] == '\0')
        return NULL;

    root = cJSON_CreateObject();
    caps = cJSON_CreateArray();
    if (!root || !caps) {
        cJSON_Delete(root);
        cJSON_Delete(caps);
        return NULL;
    }

    if (!cJSON_AddStringToObject(root, "sender", ctx->config.local_fqdn) ||
        !cJSON_AddItemToArray(caps, cJSON_CreateString(capability)) ||
        !cJSON_AddStringToObject(root,
                                "supportedFeatures",
                                N32C_SUPPORTED_FEATURES)) {
        cJSON_Delete(root);
        cJSON_Delete(caps);
        return NULL;
    }

    cJSON_AddItemToObject(root, "supportedSecCapabilityList", caps);
    if (strcmp(capability, "TLS") == 0 &&
        !cJSON_AddBoolToObject(root, "3GppSbiTargetApiRootSupported", 1)) {
        cJSON_Delete(root);
        return NULL;
    }

    if (n32c_add_local_plmn_list(ctx, root) != 0) {
        cJSON_Delete(root);
        return NULL;
    }

    body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return body;
}

static void n32c_close_timer_cb(struct sepp_timer *timer, void *arg)
{
    struct sepp_conn *conn = arg;

    (void)timer;

    if (!conn || !conn->ctx)
        return;

    SEPP_INFO("closing completed N32-C connection fd %d", conn->fd);
    sepp_conn_destroy(conn->ctx, conn);
}

static int n32c_schedule_outbound_close(struct sepp_context *ctx,
                                        struct sepp_peer_ctx *peer,
                                        struct sepp_conn *conn)
{
    if (!ctx || !peer || !conn || peer->n32c_conn != conn)
        return -1;

    if (sepp_timer_active(&peer->n32c_close_timer))
        return 0;

    return sepp_timer_start(ctx,
                            &peer->n32c_close_timer,
                            1u,
                            n32c_close_timer_cb,
                            conn);
}

static int n32c_schedule_inbound_close(struct sepp_context *ctx,
                                       struct sepp_conn *conn)
{
    if (!ctx || !conn)
        return -1;

    if (sepp_timer_active(&conn->drain_close_timer))
        return 0;

    return sepp_timer_start(ctx,
                            &conn->drain_close_timer,
                            1u,
                            n32c_close_timer_cb,
                            conn);
}

static char *n32c_build_capability_response(const struct sepp_context *ctx,
                                            const char *selected,
                                            int nftlst)
{
    cJSON *root;
    char *body;

    if (!ctx || !selected || ctx->config.local_fqdn[0] == '\0')
        return NULL;

    root = cJSON_CreateObject();
    if (!root)
        return NULL;

    if (!cJSON_AddStringToObject(root, "sender", ctx->config.local_fqdn) ||
        !cJSON_AddStringToObject(root, "selectedSecCapability", selected) ||
        (nftlst &&
         !cJSON_AddStringToObject(root,
                                 "supportedFeatures",
                                 N32C_SUPPORTED_FEATURES)) ||
        (strcmp(selected, "TLS") == 0 &&
         !cJSON_AddBoolToObject(root,
                               "3GppSbiTargetApiRootSupported",
                               1))) {
        cJSON_Delete(root);
        return NULL;
    }

    if (strcmp(selected, "TLS") == 0 &&
        n32c_add_local_plmn_list(ctx, root) != 0) {
        cJSON_Delete(root);
        return NULL;
    }

    body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return body;
}

static int n32c_complete_tls_teardown(struct sepp_context *ctx,
                                      struct sepp_peer_ctx *peer)
{
    struct sepp_target_key target;

    if (!ctx || !peer)
        return -1;

    target = peer->target;
    if (sepp_timer_active(&peer->n32c_redirect_timer))
        sepp_timer_stop(ctx, &peer->n32c_redirect_timer);

    peer->sender_fqdn[0] = '\0';
    peer->sender_n32f_fqdn[0] = '\0';
    snprintf(peer->n32c_peer_fqdn,
             sizeof(peer->n32c_peer_fqdn),
             "%s",
             peer->target.fqdn);
    peer->n32c_peer_port = peer->port;
    snprintf(peer->n32c_peer_path,
             sizeof(peer->n32c_peer_path),
             "%s",
             N32C_EXCHANGE_CAPABILITY_PATH);
    snprintf(peer->n32f_peer_fqdn,
             sizeof(peer->n32f_peer_fqdn),
             "%s",
             peer->target.fqdn);
    peer->n32f_peer_port = peer->configured_n32f_port;
    peer->n32c_redirect_count = 0;
    peer->selected_security = SEPP_SECURITY_CAPABILITY_UNKNOWN;
    peer->negotiated_features = 0;
    peer->n32c_state = SEPP_N32C_STATE_IDLE;

    return sepp_target_drain_n32f_connections(ctx, &target);
}

static int n32c_handle_exchange_capability_request(
    struct sepp_context *ctx,
    const struct sepp_msg *msg)
{
    struct sepp_peer_ctx *peer = NULL;
    cJSON *root;
    cJSON *sender;
    cJSON *sender_n32f_fqdn;
    cJSON *caps;
    cJSON *supported_features;
    cJSON *target_api_root_supported;
    char *response;
    const uint8_t *body;
    size_t body_len;
    int nftlst;
    int target_api_root;
    int teardown;
    int rc;

    body = sepp_msg_body_for_inspection(msg, &body_len);
    SEPP_DEBUG("n32c: rx exchange-capability request body (%zu bytes): %.*s",
               body_len,
               (int)body_len,
               body ? (const char *)body : "");
    root = cJSON_ParseWithLength((const char *)body, body_len);
    if (!root)
        return n32c_send_json_response(msg, 400, "{\"error\":\"invalid_json\"}\n");

    sender = cJSON_GetObjectItemCaseSensitive(root, "sender");
    sender_n32f_fqdn = cJSON_GetObjectItemCaseSensitive(root,
                                                        "senderN32fFqdn");
    caps = cJSON_GetObjectItemCaseSensitive(root,
                                            "supportedSecCapabilityList");
    supported_features = cJSON_GetObjectItemCaseSensitive(root,
                                                          "supportedFeatures");
    target_api_root_supported = cJSON_GetObjectItemCaseSensitive(
        root, "3GppSbiTargetApiRootSupported");
    target_api_root = cJSON_IsTrue(target_api_root_supported);
    if (!n32c_fqdn_ie_valid(sender, 1) ||
        !n32c_fqdn_ie_valid(sender_n32f_fqdn, 0) ||
        !cJSON_IsArray(caps) ||
        !n32c_parse_supported_features(supported_features, &nftlst) ||
        (target_api_root_supported &&
         !cJSON_IsBool(target_api_root_supported))) {
        SEPP_DEBUG("n32c: rejecting exchange-capability request: "
                   "sender_valid=%d senderN32fFqdn_valid=%d caps_is_array=%d "
                   "features_valid=%d target_api_root_type_valid=%d",
                   n32c_fqdn_ie_valid(sender, 1),
                   n32c_fqdn_ie_valid(sender_n32f_fqdn, 0),
                   cJSON_IsArray(caps),
                   n32c_parse_supported_features(supported_features, &nftlst),
                   !target_api_root_supported ||
                       cJSON_IsBool(target_api_root_supported));
        cJSON_Delete(root);
        return n32c_send_json_response(msg,
                                       400,
                                       "{\"error\":\"invalid_capability_request\"}\n");
    }

    teardown = n32c_json_array_is_single_string(caps, "NONE");
    if ((!teardown && !n32c_json_array_has_string(caps, "TLS")) ||
        (!teardown && n32c_json_array_has_string(caps, "NONE"))) {
        cJSON_Delete(root);
        return n32c_send_json_response(msg,
                                       400,
                                       "{\"error\":\"unsupported_security_capability\"}\n");
    }

    if (n32c_bind_inbound_peer(ctx,
                               msg->conn,
                               sender->valuestring,
                               &peer) != 0) {
        cJSON_Delete(root);
        return n32c_send_json_response(msg,
                                       403,
                                       "{\"error\":\"unknown_peer\"}\n");
    }

    if (teardown) {
        if (!nftlst ||
            peer->n32c_state != SEPP_N32C_STATE_ESTABLISHED ||
            peer->selected_security != SEPP_SECURITY_CAPABILITY_TLS ||
            !(peer->negotiated_features & SEPP_PEER_F_NFTLST)) {
            cJSON_Delete(root);
            return n32c_send_json_response(
                msg,
                403,
                "{\"error\":\"negotiation_not_allowed\"}\n");
        }

        cJSON_Delete(root);
        peer->n32c_state = SEPP_N32C_STATE_TERMINATING;

        response = n32c_build_capability_response(ctx, "NONE", 1);
        if (!response) {
            peer->n32c_state = SEPP_N32C_STATE_ESTABLISHED;
            return -1;
        }

        rc = n32c_send_json_response(msg, 200, response);
        free(response);
        if (rc != 0) {
            peer->n32c_state = SEPP_N32C_STATE_ESTABLISHED;
            return rc;
        }

        if (n32c_complete_tls_teardown(ctx, peer) != 0)
            SEPP_ERROR("one or more N32-F connections for %s required forced teardown",
                       peer->target.fqdn);

        SEPP_INFO("accepted N32-C TLS teardown from %s; selected NONE",
                  peer->target.fqdn);

        if (n32c_schedule_inbound_close(ctx, msg->conn) != 0) {
            SEPP_ERROR("failed to schedule inbound N32-C teardown close for %s",
                       peer->target.fqdn);
            return -1;
        }

        return 0;
    }

    n32c_store_peer_identity(peer, sender, sender_n32f_fqdn);
    cJSON_Delete(root);

    peer->negotiated_features =
        (nftlst ? SEPP_PEER_F_NFTLST : 0) |
        (target_api_root ? SEPP_PEER_F_TARGET_API_ROOT : 0);
    peer->selected_security = SEPP_SECURITY_CAPABILITY_TLS;

    response = n32c_build_capability_response(ctx, "TLS", nftlst);
    if (!response) {
        peer->n32c_state = SEPP_N32C_STATE_FAILED;
        return -1;
    }

    rc = n32c_send_json_response(msg, 200, response);
    free(response);
    if (rc != 0) {
        peer->n32c_state = SEPP_N32C_STATE_FAILED;
        return rc;
    }

    peer->n32c_state = SEPP_N32C_STATE_ESTABLISHED;

    SEPP_INFO("N32-C exchange-capability request accepted from %s; selected TLS",
              peer->target.fqdn);
    return 0;
}

static int n32c_handle_request(struct sepp_context *ctx,
                               const struct sepp_msg *msg)
{
    enum sepp_n32_operation op;

    if (msg->mime_part_count > 0)
        return n32c_send_json_response(
            msg, 415, "{\"error\":\"unsupported_media_type\"}\n");

    if (!n32c_path_matches(msg->path)) {
        SEPP_INFO("unsupported N32-C request path %s on fd %d stream %d",
                  msg->path,
                  msg->conn->fd,
                  msg->stream_id);
        return n32c_send_json_response(msg,
                                       404,
                                       "{\"error\":\"not_found\"}\n");
    }

    op = n32c_operation_from_request(msg->path);
    if (msg->stream)
        sepp_http2_stream_set_n32_operation(msg->stream, op);

    if (op == SEPP_N32C_OP_EXCHANGE_CAPABILITY) {
        if (strcmp(msg->method, "POST") != 0)
            return n32c_send_json_response(msg,
                                           405,
                                           "{\"error\":\"method_not_allowed\"}\n");
        return n32c_handle_exchange_capability_request(ctx, msg);
    }

    SEPP_INFO("N32-C request stub fd %d stream %d op=%s method=%s path=%s body=%zu",
              msg->conn->fd,
              msg->stream_id,
              sepp_n32_operation_name(op),
              msg->method,
              msg->path,
              msg->body_len);

    return n32c_send_json_response(msg,
                                   501,
                                   "{\"error\":\"n32c_not_implemented\"}\n");
}

static int n32c_handle_exchange_capability_response(
    struct sepp_context *ctx,
    const struct sepp_msg *msg)
{
    struct sepp_peer_ctx *peer;
    cJSON *root;
    cJSON *sender;
    cJSON *sender_n32f_fqdn;
    cJSON *selected;
    cJSON *supported_features;
    cJSON *target_api_root_supported;
    const char *expected_selected;
    const uint8_t *body;
    size_t body_len;
    int nftlst;
    int target_api_root;
    int teardown;

    /* Declared below; the timer defers destruction of the connection whose
     * HTTP/2 callback is currently executing. */

    peer = n32c_peer_for_outbound_conn(ctx, msg->conn);
    if (!peer)
        return -1;

    teardown = peer->n32c_state == SEPP_N32C_STATE_TERMINATING;
    if (msg->mime_part_count > 0) {
        peer->n32c_state = teardown ? SEPP_N32C_STATE_ESTABLISHED
                                    : SEPP_N32C_STATE_FAILED;
        SEPP_ERROR("N32-C peer %s returned unsupported multipart content",
                   peer->target.fqdn);
        return -1;
    }

    if (!teardown && msg->status == 307) {
        const char *location = n32c_find_header(msg, "location");

        if (peer->n32c_redirect_count >= SEPP_N32C_MAX_REDIRECTS ||
            n32c_parse_redirect_uri(location,
                                    peer->n32c_peer_fqdn,
                                    sizeof(peer->n32c_peer_fqdn),
                                    &peer->n32c_peer_port,
                                    peer->n32c_peer_path,
                                    sizeof(peer->n32c_peer_path)) != 0) {
            peer->n32c_state = SEPP_N32C_STATE_FAILED;
            SEPP_ERROR("rejected N32-C redirect for %s: invalid Location or redirect limit",
                       peer->target.fqdn);
            return -1;
        }

        peer->n32c_redirect_count++;
        peer->n32c_state = SEPP_N32C_STATE_REDIRECTING;
        if (sepp_timer_start(ctx,
                             &peer->n32c_redirect_timer,
                             1u,
                             n32c_redirect_timer_cb,
                             peer) != 0) {
            peer->n32c_state = SEPP_N32C_STATE_FAILED;
            return -1;
        }
        SEPP_INFO("following N32-C redirect %u/%u for %s to %s:%u",
                  peer->n32c_redirect_count,
                  SEPP_N32C_MAX_REDIRECTS,
                  peer->target.fqdn,
                  peer->n32c_peer_fqdn,
                  (unsigned int)peer->n32c_peer_port);
        return 0;
    }
    if (msg->status != 200) {
        peer->n32c_state = teardown ? SEPP_N32C_STATE_ESTABLISHED
                                    : SEPP_N32C_STATE_FAILED;
        SEPP_ERROR("N32-C %s failed for %s with HTTP %u",
                   teardown ? "TLS teardown" : "exchange-capability",
                   peer->target.fqdn,
                   msg->status);
        return -1;
    }

    body = sepp_msg_body_for_inspection(msg, &body_len);
    root = cJSON_ParseWithLength((const char *)body, body_len);
    if (!root) {
        peer->n32c_state = teardown ? SEPP_N32C_STATE_ESTABLISHED
                                    : SEPP_N32C_STATE_FAILED;
        return -1;
    }

    sender = cJSON_GetObjectItemCaseSensitive(root, "sender");
    sender_n32f_fqdn = cJSON_GetObjectItemCaseSensitive(root,
                                                        "senderN32fFqdn");
    selected = cJSON_GetObjectItemCaseSensitive(root,
                                                 "selectedSecCapability");
    supported_features = cJSON_GetObjectItemCaseSensitive(root,
                                                          "supportedFeatures");
    target_api_root_supported = cJSON_GetObjectItemCaseSensitive(
        root, "3GppSbiTargetApiRootSupported");
    target_api_root = cJSON_IsTrue(target_api_root_supported);
    expected_selected = teardown ? "NONE" : "TLS";
    if (!n32c_fqdn_ie_valid(sender, 1) ||
        !n32c_fqdn_ie_valid(sender_n32f_fqdn, 0) ||
        !cJSON_IsString(selected) ||
        !selected->valuestring ||
        strcmp(selected->valuestring, expected_selected) != 0 ||
        strcasecmp(sender->valuestring, peer->n32c_peer_fqdn) != 0 ||
        !n32c_parse_supported_features(supported_features, &nftlst) ||
        (target_api_root_supported &&
         !cJSON_IsBool(target_api_root_supported)) ||
        (teardown && !nftlst)) {
        cJSON_Delete(root);
        peer->n32c_state = teardown ? SEPP_N32C_STATE_ESTABLISHED
                                    : SEPP_N32C_STATE_FAILED;
        return -1;
    }

    if (teardown) {
        cJSON_Delete(root);

        if (n32c_complete_tls_teardown(ctx, peer) != 0)
            SEPP_ERROR("one or more N32-F connections for %s required forced teardown",
                       peer->target.fqdn);

        SEPP_INFO("N32-C TLS teardown completed with peer %s; selected NONE",
                  peer->target.fqdn);

        if (n32c_schedule_outbound_close(ctx, peer, msg->conn) != 0) {
            SEPP_ERROR("failed to schedule N32-C teardown close for %s",
                       peer->target.fqdn);
            return -1;
        }

        return 0;
    }

    n32c_store_peer_identity(peer, sender, sender_n32f_fqdn);
    snprintf(peer->n32f_peer_fqdn, sizeof(peer->n32f_peer_fqdn), "%s",
             sender_n32f_fqdn ? sender_n32f_fqdn->valuestring
                              : peer->n32c_peer_fqdn);
    /* 3GPP TS 29.573 carries no N32-f port in the handshake response; use
     * our own locally configured N32-f port for this peer (falls back to
     * the N32-c port when the peer co-locates both roles on one port). */
    peer->n32f_peer_port = peer->configured_n32f_port;
    peer->n32c_redirect_count = 0;
    cJSON_Delete(root);

    peer->negotiated_features =
        (nftlst ? SEPP_PEER_F_NFTLST : 0) |
        (target_api_root ? SEPP_PEER_F_TARGET_API_ROOT : 0);
    peer->selected_security = SEPP_SECURITY_CAPABILITY_TLS;
    peer->n32c_state = SEPP_N32C_STATE_ESTABLISHED;

    SEPP_INFO("N32-C exchange-capability completed with peer %s; selected TLS",
              peer->target.fqdn);

    if (n32c_schedule_outbound_close(ctx, peer, msg->conn) != 0) {
        SEPP_ERROR("failed to schedule N32-C connection close for %s",
                   peer->target.fqdn);
        return -1;
    }

    return 0;
}

static void n32c_redirect_timer_cb(struct sepp_timer *timer, void *arg)
{
    struct sepp_peer_ctx *peer = arg;
    struct sepp_context *ctx;
    struct sepp_conn *old;
    struct sepp_conn *conn;

    (void)timer;
    if (!peer || !peer->n32c_conn || !peer->n32c_conn->ctx ||
        peer->n32c_state != SEPP_N32C_STATE_REDIRECTING)
        return;

    old = peer->n32c_conn;
    ctx = old->ctx;
    sepp_conn_destroy(ctx, old);
    peer->n32c_state = SEPP_N32C_STATE_CONNECTING;
    conn = sepp_connector_get_or_connect_type(ctx,
                                              &peer->target,
                                              peer->n32c_peer_fqdn,
                                              peer->n32c_peer_port,
                                              SEPP_CONN_TYPE_N32C);
    if (!conn) {
        peer->n32c_state = SEPP_N32C_STATE_FAILED;
        SEPP_ERROR("failed to connect to redirected N32-C peer %s:%u",
                   peer->n32c_peer_fqdn,
                   (unsigned int)peer->n32c_peer_port);
    }
}

int sepp_n32c_on_conn_ready(struct sepp_context *ctx, struct sepp_conn *conn)
{
    struct sepp_peer_ctx *peer;
    char authority[SEPP_TARGET_FQDN_MAX + 16u];
    char *body;
    int32_t stream_id;
    int teardown;

    if (!ctx || !conn || conn->type != SEPP_CONN_TYPE_N32C ||
        !(conn->flags & SEPP_CONN_F_OUTBOUND))
        return -1;

    peer = n32c_peer_for_outbound_conn(ctx, conn);
    if (!peer)
        return -1;

    SEPP_DEBUG("n32c: conn ready for peer %s on fd %d, current state=%s",
               peer->target.fqdn,
               conn->fd,
               sepp_n32c_state_name(peer->n32c_state));

    teardown = peer->n32c_state == SEPP_N32C_STATE_TERMINATING;
    if (peer->n32c_state == SEPP_N32C_STATE_EXCHANGE_CAPABILITY ||
        peer->n32c_state == SEPP_N32C_STATE_ESTABLISHED)
        return 0;

    body = n32c_build_capability_request(ctx, teardown ? "NONE" : "TLS");
    if (!body) {
        peer->n32c_state = teardown ? SEPP_N32C_STATE_ESTABLISHED
                                    : SEPP_N32C_STATE_FAILED;
        SEPP_ERROR("local_fqdn is required for N32-C capability exchange");
        return -1;
    }

    if (peer->n32c_peer_port == 443)
        snprintf(authority, sizeof(authority), "%s", peer->n32c_peer_fqdn);
    else
        snprintf(authority,
                 sizeof(authority),
                 "%s:%u",
                 peer->n32c_peer_fqdn,
                 (unsigned int)peer->n32c_peer_port);

    stream_id = sepp_http2_submit_request(conn,
                                          "POST",
                                          "https",
                                          authority,
                                          peer->n32c_peer_path,
                                          "application/json",
                                          NULL,
                                          NULL,
                                          NULL,
                                          NULL,
                                          0,
                                          (const unsigned char *)body,
                                          strlen(body));
    free(body);

    if (stream_id <= 0 ||
        sepp_http2_expect_response(conn,
                                   stream_id,
                                   SEPP_N32C_OP_EXCHANGE_CAPABILITY) != 0) {
        peer->n32c_state = teardown ? SEPP_N32C_STATE_ESTABLISHED
                                    : SEPP_N32C_STATE_FAILED;
        return -1;
    }

    if (!teardown)
        peer->n32c_state = SEPP_N32C_STATE_EXCHANGE_CAPABILITY;
    SEPP_INFO("sent N32-C %s to %s on fd %d stream %d",
              teardown ? "TLS teardown" : "exchange-capability",
              peer->n32c_peer_fqdn,
              conn->fd,
              stream_id);
    return 0;
}

int sepp_n32c_start_tls_teardown(struct sepp_context *ctx,
                                 const struct sepp_target_key *key)
{
    struct sepp_peer_ctx *peer;
    struct sepp_conn *conn;

    if (!ctx || !key || key->type != SEPP_TARGET_PEER_SEPP)
        return -1;

    peer = sepp_peer_lookup_target(&ctx->peer_table, key);
    if (!peer)
        return -1;

    if (peer->n32c_state == SEPP_N32C_STATE_TERMINATING)
        return 0;

    if (peer->n32c_state != SEPP_N32C_STATE_ESTABLISHED ||
        peer->selected_security != SEPP_SECURITY_CAPABILITY_TLS ||
        !(peer->negotiated_features & SEPP_PEER_F_NFTLST) ||
        peer->n32c_conn)
        return -1;

    peer->n32c_state = SEPP_N32C_STATE_TERMINATING;
    conn = sepp_connector_get_or_connect_type(ctx,
                                              key,
                                              peer->n32c_peer_fqdn,
                                              peer->n32c_peer_port,
                                              SEPP_CONN_TYPE_N32C);
    if (!conn) {
        peer->n32c_state = SEPP_N32C_STATE_ESTABLISHED;
        return -1;
    }

    SEPP_INFO("started N32-C TLS teardown connection fd %d for peer %s:%u",
              conn->fd,
              peer->n32c_peer_fqdn,
              (unsigned int)peer->n32c_peer_port);
    return 0;
}

int sepp_n32c_handle_msg(struct sepp_context *ctx,
                         const struct sepp_msg *msg)
{
    enum sepp_n32_operation op;

    if (!ctx || !msg)
        return -1;

    if (msg->type == SEPP_MSG_TYPE_REQUEST)
        return n32c_handle_request(ctx, msg);

    if (msg->type == SEPP_MSG_TYPE_RESPONSE) {
        op = msg->n32_operation;
        if (op == SEPP_N32C_OP_EXCHANGE_CAPABILITY)
            return n32c_handle_exchange_capability_response(ctx, msg);

        SEPP_INFO("N32-C response stub fd %d stream %d op=%s status=%u",
                  msg->conn ? msg->conn->fd : -1,
                  msg->stream_id,
                  sepp_n32_operation_name(op),
                  msg->status);
        return 0;
    }

    SEPP_ERROR("unsupported N32-C message type %d on stream %d",
               msg->type,
               msg->stream_id);
    return -1;
}
