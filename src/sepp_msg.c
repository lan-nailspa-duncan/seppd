#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "connection.h"
#include "http2.h"
#include "log.h"
#include "sepp.h"
#include "sepp_msg.h"
#include "sbi.h"

static int sepp_msg_default_handler(struct sepp_context *ctx,
                                    const struct sepp_msg *msg,
                                    void *arg)
{
    (void)ctx;
    (void)arg;

    if (!msg || !msg->conn)
        return -1;

    if (msg->type == SEPP_MSG_TYPE_REQUEST) {
        SEPP_INFO("SEPP HTTP request fd %d stream %d method=%s path=%s headers=%zu body=%zu",
                  msg->conn->fd,
                  msg->stream_id,
                  msg->method,
                  msg->path,
                  msg->header_count,
                  msg->body_len);
    } else if (msg->type == SEPP_MSG_TYPE_RESPONSE) {
        SEPP_INFO("SEPP HTTP response fd %d stream %d status=%u headers=%zu body=%zu",
                  msg->conn->fd,
                  msg->stream_id,
                  msg->status,
                  msg->header_count,
                  msg->body_len);
    } else {
        SEPP_INFO("SEPP HTTP message fd %d stream %d headers=%zu body=%zu",
                  msg->conn->fd,
                  msg->stream_id,
                  msg->header_count,
                  msg->body_len);
    }

    return 0;
}

static void sepp_msg_copy_value(char *dst,
                                size_t dst_len,
                                const char *src)
{
    if (!dst || dst_len == 0)
        return;

    dst[0] = '\0';

    if (!src)
        return;

    snprintf(dst, dst_len, "%s", src);
}

static unsigned int sepp_msg_parse_status(const char *value)
{
    unsigned long status;
    char *endptr;

    if (!value || value[0] == '\0')
        return SEPP_MSG_STATUS_NONE;

    status = strtoul(value, &endptr, 10);
    if (endptr == value || *endptr != '\0' || status > 999ul)
        return SEPP_MSG_STATUS_NONE;

    return (unsigned int)status;
}

static const char *sepp_msg_find_header(const struct sepp_http2_msg *h2msg,
                                        const char *name)
{
    size_t i;

    if (!h2msg || !name)
        return NULL;

    for (i = 0; i < h2msg->header_count; i++) {
        if (!h2msg->headers[i].name)
            continue;

        if (strcmp(h2msg->headers[i].name, name) == 0)
            return h2msg->headers[i].value;
    }

    return NULL;
}

static void sepp_msg_from_http2(struct sepp_msg *msg,
                                struct sepp_conn *conn,
                                const struct sepp_http2_msg *h2msg)
{
    const char *value;

    memset(msg, 0, sizeof(*msg));

    msg->conn = conn;
    msg->stream_id = h2msg->stream_id;
    msg->stream = h2msg->stream;
    msg->type = h2msg->is_request ? SEPP_MSG_TYPE_REQUEST : SEPP_MSG_TYPE_RESPONSE;
    msg->n32_operation = h2msg->n32_operation;
    msg->headers = h2msg->headers;
    msg->header_count = h2msg->header_count;
    msg->content_type = sepp_msg_find_header(h2msg, "content-type");
    msg->body = h2msg->body;
    msg->body_len = h2msg->body_len;
    msg->decoded_body = h2msg->decoded_body;
    msg->decoded_body_len = h2msg->decoded_body_len;
    msg->mime_parts = h2msg->mime_parts;
    msg->mime_part_count = h2msg->mime_part_count;

    sepp_sbi_headers_parse(&msg->sbi, h2msg->headers, h2msg->header_count);

    value = sepp_msg_find_header(h2msg, ":method");
    sepp_msg_copy_value(msg->method, sizeof(msg->method), value);

    value = sepp_msg_find_header(h2msg, ":path");
    sepp_msg_copy_value(msg->path, sizeof(msg->path), value);

    value = sepp_msg_find_header(h2msg, ":authority");
    sepp_msg_copy_value(msg->authority, sizeof(msg->authority), value);

    value = sepp_msg_find_header(h2msg, ":scheme");
    sepp_msg_copy_value(msg->scheme, sizeof(msg->scheme), value);

    value = sepp_msg_find_header(h2msg, ":status");
    msg->status = sepp_msg_parse_status(value);
}

static int sepp_msg_validate(const struct sepp_msg *msg)
{
    if (!msg)
        return -1;

    if (msg->type == SEPP_MSG_TYPE_REQUEST) {
        if (msg->method[0] == '\0' || msg->path[0] == '\0') {
            SEPP_ERROR("HTTP/2 request stream %d missing required pseudo-headers",
                       msg->stream_id);
            return -1;
        }
    } else if (msg->type == SEPP_MSG_TYPE_RESPONSE) {
        if (msg->status == SEPP_MSG_STATUS_NONE) {
            SEPP_ERROR("HTTP/2 response stream %d missing or invalid :status",
                       msg->stream_id);
            return -1;
        }
    }

    return 0;
}

static void sepp_msg_http2_cb(struct sepp_conn *conn,
                              const struct sepp_http2_msg *h2msg,
                              void *arg)
{
    struct sepp_context *ctx = arg;
    struct sepp_msg msg;
    sepp_msg_cb cb;
    void *cb_arg;

    if (!ctx || !conn || !h2msg)
        return;

    sepp_msg_from_http2(&msg, conn, h2msg);
    if (sepp_msg_validate(&msg) != 0)
        return;

    cb = ctx->msg_dispatcher.cb;
    cb_arg = ctx->msg_dispatcher.arg;

    if (!cb)
        cb = sepp_msg_default_handler;

    if (cb(ctx, &msg, cb_arg) != 0) {
        SEPP_ERROR("SEPP message handler failed fd %d stream %d",
                   conn->fd,
                   msg.stream_id);
        sepp_conn_destroy(ctx, conn);
    }
}

void sepp_msg_dispatcher_init(struct sepp_msg_dispatcher *dispatcher)
{
    if (!dispatcher)
        return;

    dispatcher->cb = sepp_msg_default_handler;
    dispatcher->arg = NULL;
}

void sepp_msg_dispatcher_cleanup(struct sepp_msg_dispatcher *dispatcher)
{
    if (!dispatcher)
        return;

    dispatcher->cb = NULL;
    dispatcher->arg = NULL;
}

void sepp_msg_set_handler(struct sepp_msg_dispatcher *dispatcher,
                          sepp_msg_cb cb,
                          void *arg)
{
    if (!dispatcher)
        return;

    dispatcher->cb = cb ? cb : sepp_msg_default_handler;
    dispatcher->arg = arg;
}

int sepp_msg_attach_http2(struct sepp_context *ctx, struct sepp_conn *conn)
{
    if (!ctx || !conn)
        return -1;

    return sepp_http2_set_msg_cb(conn, sepp_msg_http2_cb, ctx);
}

const uint8_t *sepp_msg_body_for_inspection(const struct sepp_msg *msg,
                                            size_t *body_len)
{
    if (!msg || !body_len)
        return NULL;

    if (msg->decoded_body) {
        *body_len = msg->decoded_body_len;
        return msg->decoded_body;
    }

    *body_len = msg->body_len;
    return msg->body;
}

int sepp_msg_content_is_json(const struct sepp_msg *msg)
{
    return msg && sepp_mime_content_type_is_json(msg->content_type);
}
