#ifndef HTTP2_H
#define HTTP2_H

#include <stddef.h>
#include <stdint.h>

#include "list.h"
#include "mime.h"
#include "n32.h"

struct sepp_conn;
struct sepp_http2;

#define SEPP_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS 1024u
#define SEPP_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE    1048576u
#define SEPP_HTTP2_SETTINGS_MAX_FRAME_SIZE         16384u
#define SEPP_HTTP2_SETTINGS_HEADER_TABLE_SIZE      4096u
#define SEPP_HTTP2_SETTINGS_ENABLE_PUSH            0u

/* Bound the representation created only for local parsing/inspection. */
#define SEPP_HTTP2_DECODED_BODY_MAX (16u * 1024u * 1024u)

/* Client streams use odd 31-bit IDs.  Keep enough IDs in reserve for a
 * replacement TLS connection to become ready before this session is full. */
#define SEPP_HTTP2_STREAM_ID_LIMIT             (1u << 31)
#define SEPP_HTTP2_STREAM_ID_ROTATION_RESERVE  (1u << 26)

struct sepp_http2_header {
    char *name;
    char *value;
};

struct sepp_http2_stream {
    int32_t stream_id;
    int is_request;
    enum sepp_n32_operation n32_operation;

    struct sepp_http2_header *headers;
    size_t header_count;
    size_t header_cap;

    uint8_t *body;
    size_t body_len;
    size_t body_cap;

    uint8_t *decoded_body;
    size_t decoded_body_len;

    struct sepp_multipart multipart;

    struct sepp_list hash_node;
};

struct sepp_http2_msg {
    int32_t stream_id;
    int is_request;
    struct sepp_http2_stream *stream;
    enum sepp_n32_operation n32_operation;

    const struct sepp_http2_header *headers;
    size_t header_count;

    const uint8_t *body;
    size_t body_len;

    const uint8_t *decoded_body;
    size_t decoded_body_len;

    const struct sepp_mime_part *mime_parts;
    size_t mime_part_count;
};

typedef void (*sepp_http2_msg_cb)(struct sepp_conn *conn,
                                  const struct sepp_http2_msg *msg,
                                  void *arg);

struct sepp_http2_stream *sepp_http2_stream_lookup(struct sepp_conn *conn,
                                                   int32_t stream_id);

void sepp_http2_stream_set_n32_operation(struct sepp_http2_stream *stream,
                                         enum sepp_n32_operation op);

enum sepp_n32_operation
sepp_http2_stream_get_n32_operation(const struct sepp_http2_stream *stream);

int sepp_http2_expect_response(struct sepp_conn *conn,
                               int32_t stream_id,
                               enum sepp_n32_operation op);

int sepp_http2_needs_rotation(const struct sepp_conn *conn);

int sepp_http2_submit_request(struct sepp_conn *conn,
                              const char *method,
                              const char *scheme,
                              const char *authority,
                              const char *path,
                              const char *content_type,
                              const char *target_api_root,
                              const char *content_encoding,
                              const char *local_via,
                              const struct sepp_http2_header *headers,
                              size_t header_count,
                              const unsigned char *body,
                              size_t body_len);

int sepp_http2_submit_response(struct sepp_conn *conn,
                               int32_t stream_id,
                               unsigned int status,
                               const char *content_type,
                               const char *content_encoding,
                               const char *local_via,
                               const struct sepp_http2_header *headers,
                               size_t header_count,
                               const unsigned char *body,
                               size_t body_len);

int sepp_http2_start(struct sepp_conn *conn, int is_server);
void sepp_http2_destroy(struct sepp_conn *conn);

int sepp_http2_set_msg_cb(struct sepp_conn *conn,
                          sepp_http2_msg_cb cb,
                          void *arg);

int sepp_http2_on_readable(struct sepp_conn *conn);
int sepp_http2_on_writable(struct sepp_conn *conn);
int sepp_http2_want_write(const struct sepp_conn *conn);

#endif /* HTTP2_H */
