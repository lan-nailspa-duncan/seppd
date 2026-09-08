#ifndef SEPP_MSG_H
#define SEPP_MSG_H

#include <stddef.h>
#include <stdint.h>

#include "http2.h"
#include "sbi.h"

struct sepp_conn;
struct sepp_context;

#define SEPP_MSG_METHOD_MAX    32
#define SEPP_MSG_PATH_MAX      1024
#define SEPP_MSG_AUTHORITY_MAX 256
#define SEPP_MSG_SCHEME_MAX    16

#define SEPP_MSG_STATUS_NONE   0

enum sepp_msg_type {
    SEPP_MSG_TYPE_UNKNOWN = 0,
    SEPP_MSG_TYPE_REQUEST,
    SEPP_MSG_TYPE_RESPONSE,
};

struct sepp_msg {
    struct sepp_conn *conn;
    int32_t stream_id;
    struct sepp_http2_stream *stream;
    enum sepp_msg_type type;
    enum sepp_n32_operation n32_operation;

    char method[SEPP_MSG_METHOD_MAX];
    char path[SEPP_MSG_PATH_MAX];
    char authority[SEPP_MSG_AUTHORITY_MAX];
    char scheme[SEPP_MSG_SCHEME_MAX];
    unsigned int status;

    struct sepp_sbi_headers sbi;

    const struct sepp_http2_header *headers;
    size_t header_count;
    const char *content_type;

    const uint8_t *body;
    size_t body_len;

    const uint8_t *decoded_body;
    size_t decoded_body_len;

    const struct sepp_mime_part *mime_parts;
    size_t mime_part_count;
};

typedef int (*sepp_msg_cb)(struct sepp_context *ctx,
                           const struct sepp_msg *msg,
                           void *arg);

struct sepp_msg_dispatcher {
    sepp_msg_cb cb;
    void *arg;
};

void sepp_msg_dispatcher_init(struct sepp_msg_dispatcher *dispatcher);
void sepp_msg_dispatcher_cleanup(struct sepp_msg_dispatcher *dispatcher);

void sepp_msg_set_handler(struct sepp_msg_dispatcher *dispatcher,
                          sepp_msg_cb cb,
                          void *arg);

int sepp_msg_attach_http2(struct sepp_context *ctx, struct sepp_conn *conn);

const uint8_t *sepp_msg_body_for_inspection(const struct sepp_msg *msg,
                                            size_t *body_len);
int sepp_msg_content_is_json(const struct sepp_msg *msg);

#endif /* SEPP_MSG_H */
