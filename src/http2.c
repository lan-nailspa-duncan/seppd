#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/epoll.h>

#include <nghttp2/nghttp2.h>
#include <zlib.h>

#include "channel.h"
#include "connection.h"
#include "event.h"
#include "http2.h"
#include "list.h"
#include "log.h"
#include "object_counter.h"
#include "sepp.h"

#define SEPP_HTTP2_READ_BUF_SIZE 16384
#define SEPP_HTTP2_STREAM_BUCKETS 256u

struct sepp_http2_out_body {
    int32_t stream_id;
    uint8_t *data;
    size_t len;
    size_t off;
    struct sepp_list node;
};

struct sepp_http2 {
    nghttp2_session *session;
    struct sepp_conn *conn;
    int is_server;

    struct sepp_list stream_buckets[SEPP_HTTP2_STREAM_BUCKETS];
    struct sepp_list out_bodies;

    sepp_http2_msg_cb msg_cb;
    void *msg_arg;
};

static unsigned int http2_stream_hash(int32_t stream_id)
{
    return ((unsigned int)stream_id) % SEPP_HTTP2_STREAM_BUCKETS;
}

static struct sepp_http2_out_body *http2_out_body_lookup(struct sepp_http2 *h2,
                                                         int32_t stream_id)
{
    struct sepp_list *pos;

    if (!h2)
        return NULL;

    sepp_list_for_each(pos, &h2->out_bodies) {
        struct sepp_http2_out_body *body;

        body = sepp_list_entry(pos, struct sepp_http2_out_body, node);
        if (body->stream_id == stream_id)
            return body;
    }

    return NULL;
}

static void http2_out_body_free(struct sepp_http2_out_body *body)
{
    if (!body)
        return;

    if (!sepp_list_empty(&body->node))
        sepp_list_del(&body->node);

    free(body->data);
    sepp_object_counter_free(SEPP_OBJECT_HTTP2_OUT_BODY);
    free(body);
}


static struct sepp_http2_stream *http2_stream_lookup(struct sepp_http2 *h2,
                                                     int32_t stream_id)
{
    struct sepp_list *head;
    struct sepp_list *pos;

    if (!h2)
        return NULL;

    head = &h2->stream_buckets[http2_stream_hash(stream_id)];

    sepp_list_for_each(pos, head) {
        struct sepp_http2_stream *stream;

        stream = sepp_list_entry(pos, struct sepp_http2_stream, hash_node);
        if (stream->stream_id == stream_id)
            return stream;
    }

    return NULL;
}

static void http2_stream_free(struct sepp_http2_stream *stream)
{
    size_t i;

    if (!stream)
        return;

    if (!sepp_list_empty(&stream->hash_node))
        sepp_list_del(&stream->hash_node);

    for (i = 0; i < stream->header_count; i++) {
        free(stream->headers[i].name);
        free(stream->headers[i].value);
        sepp_object_counter_free(SEPP_OBJECT_HTTP2_HEADER);
    }

    free(stream->headers);
    free(stream->body);
    sepp_multipart_cleanup(&stream->multipart);
    free(stream->decoded_body);
    sepp_object_counter_free(SEPP_OBJECT_HTTP2_STREAM);
    free(stream);
}

static const char *http2_stream_find_header(
    const struct sepp_http2_stream *stream,
    const char *name)
{
    size_t i;

    if (!stream || !name)
        return NULL;

    for (i = 0; i < stream->header_count; i++) {
        if (stream->headers[i].name &&
            strcasecmp(stream->headers[i].name, name) == 0)
            return stream->headers[i].value;
    }

    return NULL;
}

static int http2_content_encoding_is(const char *value, const char *encoding)
{
    const char *end;
    size_t encoding_len;

    if (!value || !encoding)
        return 0;

    while (*value == ' ' || *value == '\t')
        value++;
    end = value + strlen(value);
    while (end > value && (end[-1] == ' ' || end[-1] == '\t'))
        end--;

    encoding_len = strlen(encoding);
    return (size_t)(end - value) == encoding_len &&
           strncasecmp(value, encoding, encoding_len) == 0;
}

static int http2_stream_decode_gzip(struct sepp_http2_stream *stream)
{
    z_stream zs;
    uint8_t *decoded = NULL;
    uint8_t output[16384];
    size_t decoded_len = 0;
    size_t decoded_cap = 0;
    size_t input_off = 0;
    int zrc;

    if (!stream || !stream->body || stream->body_len == 0)
        return -1;

    memset(&zs, 0, sizeof(zs));
    zrc = inflateInit2(&zs, 16 + MAX_WBITS);
    if (zrc != Z_OK)
        return -1;

    do {
        size_t input_left;
        size_t produced;
        uint8_t *new_decoded;

        if (zs.avail_in == 0 && input_off < stream->body_len) {
            input_left = stream->body_len - input_off;
            zs.next_in = stream->body + input_off;
            zs.avail_in = input_left > UINT_MAX ? UINT_MAX : (uInt)input_left;
            input_off += zs.avail_in;
        }

        zs.next_out = output;
        zs.avail_out = sizeof(output);
        zrc = inflate(&zs, Z_NO_FLUSH);
        produced = sizeof(output) - zs.avail_out;
        if (produced > SEPP_HTTP2_DECODED_BODY_MAX - decoded_len) {
            zrc = Z_MEM_ERROR;
            break;
        }
        if (produced > 0) {
            size_t required = decoded_len + produced;

            if (required > decoded_cap) {
                size_t new_cap = decoded_cap ? decoded_cap * 2u
                                             : sizeof(output);

                while (new_cap < required)
                    new_cap *= 2u;
                if (new_cap > SEPP_HTTP2_DECODED_BODY_MAX)
                    new_cap = SEPP_HTTP2_DECODED_BODY_MAX;

                new_decoded = realloc(decoded, new_cap);
                if (!new_decoded) {
                    zrc = Z_MEM_ERROR;
                    break;
                }
                decoded = new_decoded;
                decoded_cap = new_cap;
            }
            memcpy(decoded + decoded_len, output, produced);
            decoded_len += produced;
        }
    } while (zrc == Z_OK);

    inflateEnd(&zs);
    if (zrc != Z_STREAM_END || input_off != stream->body_len || zs.avail_in != 0) {
        free(decoded);
        return -1;
    }

    if (!decoded) {
        decoded = malloc(1u);
        if (!decoded)
            return -1;
    }

    stream->decoded_body = decoded;
    stream->decoded_body_len = decoded_len;
    return 0;
}

static int http2_stream_decode_body(struct sepp_http2_stream *stream)
{
    const char *content_encoding;

    content_encoding = http2_stream_find_header(stream, "content-encoding");
    if (!content_encoding ||
        http2_content_encoding_is(content_encoding, "identity"))
        return 0;

    if (!http2_content_encoding_is(content_encoding, "gzip"))
        return -2;

    return http2_stream_decode_gzip(stream);
}

static int http2_stream_parse_multipart(struct sepp_http2_stream *stream)
{
    const char *content_type;
    const uint8_t *body;
    size_t body_len;
    int rc;

    if (!stream)
        return -1;

    content_type = http2_stream_find_header(stream, "content-type");
    if (stream->decoded_body) {
        body = stream->decoded_body;
        body_len = stream->decoded_body_len;
    } else {
        body = stream->body;
        body_len = stream->body_len;
    }

    rc = sepp_multipart_parse(&stream->multipart,
                              content_type,
                              body,
                              body_len);
    return rc < 0 ? -1 : 0;
}

static int http2_stream_prepare_body(struct sepp_http2_stream *stream)
{
    int rc;

    rc = http2_stream_decode_body(stream);
    if (rc != 0)
        return rc;

    if (http2_stream_parse_multipart(stream) != 0)
        return -3;

    return 0;
}

static struct sepp_http2_stream *http2_stream_create(struct sepp_http2 *h2,
                                                     int32_t stream_id,
                                                     int is_request)
{
    struct sepp_http2_stream *stream;
    struct sepp_list *head;

    stream = http2_stream_lookup(h2, stream_id);
    if (stream)
        return stream;

    stream = calloc(1, sizeof(*stream));
    if (!stream)
        return NULL;
    sepp_object_counter_alloc(SEPP_OBJECT_HTTP2_STREAM);

    stream->stream_id = stream_id;
    stream->is_request = is_request;
    sepp_list_init(&stream->hash_node);

    head = &h2->stream_buckets[http2_stream_hash(stream_id)];
    sepp_list_add(&stream->hash_node, head);

    return stream;
}

static int http2_stream_append_header(struct sepp_http2_stream *stream,
                                      const uint8_t *name,
                                      size_t namelen,
                                      const uint8_t *value,
                                      size_t valuelen)
{
    struct sepp_http2_header *headers;
    char *hname;
    char *hvalue;
    size_t new_cap;

    if (stream->header_count == stream->header_cap) {
        new_cap = stream->header_cap ? stream->header_cap * 2u : 16u;
        headers = realloc(stream->headers, new_cap * sizeof(*headers));
        if (!headers)
            return -1;
        stream->headers = headers;
        stream->header_cap = new_cap;
    }

    hname = malloc(namelen + 1u);
    if (!hname)
        return -1;

    hvalue = malloc(valuelen + 1u);
    if (!hvalue) {
        free(hname);
        return -1;
    }

    memcpy(hname, name, namelen);
    hname[namelen] = '\0';

    memcpy(hvalue, value, valuelen);
    hvalue[valuelen] = '\0';

    stream->headers[stream->header_count].name = hname;
    stream->headers[stream->header_count].value = hvalue;
    stream->header_count++;
    sepp_object_counter_alloc(SEPP_OBJECT_HTTP2_HEADER);

    return 0;
}

static int http2_stream_append_body(struct sepp_http2_stream *stream,
                                    const uint8_t *data,
                                    size_t len)
{
    uint8_t *body;
    size_t new_cap;
    size_t required;

    if (len == 0)
        return 0;

    required = stream->body_len + len;
    if (required < stream->body_len)
        return -1;

    if (required > stream->body_cap) {
        new_cap = stream->body_cap ? stream->body_cap * 2u : 4096u;
        while (new_cap < required) {
            size_t next_cap = new_cap * 2u;

            if (next_cap <= new_cap)
                return -1;
            new_cap = next_cap;
        }

        body = realloc(stream->body, new_cap);
        if (!body)
            return -1;

        stream->body = body;
        stream->body_cap = new_cap;
    }

    memcpy(stream->body + stream->body_len, data, len);
    stream->body_len += len;

    return 0;
}

static void http2_dispatch_msg(struct sepp_http2 *h2,
                               struct sepp_http2_stream *stream)
{
    struct sepp_http2_msg msg;

    if (!h2 || !stream)
        return;

    memset(&msg, 0, sizeof(msg));
    msg.stream_id = stream->stream_id;
    msg.is_request = stream->is_request;
    msg.stream = stream;
    msg.n32_operation = stream->n32_operation;
    msg.headers = stream->headers;
    msg.header_count = stream->header_count;
    msg.body = stream->body;
    msg.body_len = stream->body_len;
    msg.decoded_body = stream->decoded_body;
    msg.decoded_body_len = stream->decoded_body_len;
    msg.mime_parts = stream->multipart.parts;
    msg.mime_part_count = stream->multipart.part_count;

    SEPP_DEBUG("HTTP/2 complete %s stream %d on fd %d: %zu headers, %zu body bytes",
               stream->is_request ? "request" : "response",
               stream->stream_id,
               h2->conn->fd,
               stream->header_count,
               stream->body_len);

    if (h2->msg_cb)
        h2->msg_cb(h2->conn, &msg, h2->msg_arg);
}

static int http2_complete_stream(struct sepp_http2 *h2, int32_t stream_id)
{
    struct sepp_http2_stream *stream;
    int decode_rc;

    stream = http2_stream_lookup(h2, stream_id);
    if (!stream) {
        SEPP_DEBUG("HTTP/2 stream %d completed on fd %d without stream state",
                   stream_id,
                   h2->conn->fd);
        return 0;
    }

    decode_rc = http2_stream_prepare_body(stream);
    if (decode_rc != 0) {
        const char *error = decode_rc == -3 ? "invalid_multipart"
                                            : "invalid_content_encoding";

        SEPP_ERROR("HTTP/2 stream %d on fd %d has %s",
                   stream_id, h2->conn->fd, error);
        if (stream->is_request) {
            unsigned char invalid_body[96];
            unsigned int status = decode_rc == -2 ? 415u : 400u;
            int body_len;

            body_len = snprintf((char *)invalid_body,
                                sizeof(invalid_body),
                                "{\"error\":\"%s\"}\n",
                                error);
            if (body_len < 0 || (size_t)body_len >= sizeof(invalid_body)) {
                http2_stream_free(stream);
                return -1;
            }

            if (sepp_http2_submit_response(h2->conn,
                                           stream_id,
                                           status,
                                           "application/json",
                                           NULL,
                                           NULL,
                                           NULL,
                                           0,
                                           invalid_body,
                                           (size_t)body_len) != 0) {
                http2_stream_free(stream);
                return -1;
            }
            http2_stream_free(stream);
            return 0;
        }
        http2_stream_free(stream);
        return -1;
    }

    http2_dispatch_msg(h2, stream);
    http2_stream_free(stream);

    return 0;
}

static ssize_t http2_response_read_cb(nghttp2_session *session,
                                      int32_t stream_id,
                                      uint8_t *buf,
                                      size_t length,
                                      uint32_t *data_flags,
                                      nghttp2_data_source *source,
                                      void *user_data)
{
    struct sepp_http2_out_body *body = source->ptr;
    size_t remaining;
    size_t ncopy;

    (void)session;
    (void)stream_id;
    (void)user_data;

    if (!body)
        return NGHTTP2_ERR_CALLBACK_FAILURE;

    remaining = body->len - body->off;
    ncopy = remaining < length ? remaining : length;

    if (ncopy > 0) {
        memcpy(buf, body->data + body->off, ncopy);
        body->off += ncopy;
    }

    if (body->off == body->len)
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;

    return (ssize_t)ncopy;
}

static ssize_t http2_send_cb(nghttp2_session *session,
                             const uint8_t *data,
                             size_t length,
                             int flags,
                             void *user_data)
{
    struct sepp_conn *conn = user_data;
    ssize_t nwritten;

    (void)session;
    (void)flags;

    nwritten = sepp_channel_write(conn, data, length);
    if (nwritten < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return NGHTTP2_ERR_WOULDBLOCK;
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    return nwritten;
}

static int http2_on_begin_headers_cb(nghttp2_session *session,
                                     const nghttp2_frame *frame,
                                     void *user_data)
{
    struct sepp_conn *conn = user_data;
    struct sepp_http2 *h2;
    int is_request;

    (void)session;

    if (!conn || !conn->http2)
        return NGHTTP2_ERR_CALLBACK_FAILURE;

    h2 = conn->http2;

    switch (frame->headers.cat) {
    case NGHTTP2_HCAT_REQUEST:
        is_request = 1;
        break;
    case NGHTTP2_HCAT_RESPONSE:
        is_request = 0;
        break;
    case NGHTTP2_HCAT_HEADERS:
        return 0;
    default:
        return 0;
    }

    if (!http2_stream_create(h2, frame->hd.stream_id, is_request))
        return NGHTTP2_ERR_CALLBACK_FAILURE;

    return 0;
}

static int http2_on_header_cb(nghttp2_session *session,
                              const nghttp2_frame *frame,
                              const uint8_t *name,
                              size_t namelen,
                              const uint8_t *value,
                              size_t valuelen,
                              uint8_t flags,
                              void *user_data)
{
    struct sepp_conn *conn = user_data;
    struct sepp_http2_stream *stream;

    (void)session;
    (void)flags;

    if (!conn || !conn->http2)
        return NGHTTP2_ERR_CALLBACK_FAILURE;

    if (frame->hd.type != NGHTTP2_HEADERS)
        return 0;

    stream = http2_stream_lookup(conn->http2, frame->hd.stream_id);
    if (!stream)
        return 0;

    if (http2_stream_append_header(stream,
                                   name,
                                   namelen,
                                   value,
                                   valuelen) != 0)
        return NGHTTP2_ERR_CALLBACK_FAILURE;

    return 0;
}

static int http2_on_data_chunk_recv_cb(nghttp2_session *session,
                                       uint8_t flags,
                                       int32_t stream_id,
                                       const uint8_t *data,
                                       size_t len,
                                       void *user_data)
{
    struct sepp_conn *conn = user_data;
    struct sepp_http2_stream *stream;

    (void)session;
    (void)flags;

    if (!conn || !conn->http2)
        return NGHTTP2_ERR_CALLBACK_FAILURE;

    stream = http2_stream_lookup(conn->http2, stream_id);
    if (!stream) {
        SEPP_ERROR("HTTP/2 DATA received for unknown stream %d on fd %d",
                   stream_id,
                   conn->fd);
        return NGHTTP2_ERR_PROTO;
    }

    if (http2_stream_append_body(stream, data, len) != 0)
        return NGHTTP2_ERR_CALLBACK_FAILURE;

    return 0;
}

static int http2_on_frame_recv_cb(nghttp2_session *session,
                                  const nghttp2_frame *frame,
                                  void *user_data)
{
    struct sepp_conn *conn = user_data;

    (void)session;

    switch (frame->hd.type) {
    case NGHTTP2_SETTINGS:
        if ((frame->hd.flags & NGHTTP2_FLAG_ACK) != 0)
            SEPP_DEBUG("HTTP/2 SETTINGS ACK received on fd %d", conn->fd);
        else
            SEPP_DEBUG("HTTP/2 SETTINGS received on fd %d", conn->fd);
        break;
    case NGHTTP2_HEADERS:
        if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0)
            return http2_complete_stream(conn->http2, frame->hd.stream_id);
        break;
    case NGHTTP2_DATA:
        if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0)
            return http2_complete_stream(conn->http2, frame->hd.stream_id);
        break;
    case NGHTTP2_GOAWAY:
        SEPP_INFO("HTTP/2 GOAWAY received on fd %d", conn->fd);
        break;
    default:
        SEPP_DEBUG("HTTP/2 frame type %u received on fd %d",
                   frame->hd.type,
                   conn->fd);
        break;
    }

    return 0;
}

static int http2_on_stream_close_cb(nghttp2_session *session,
                                    int32_t stream_id,
                                    uint32_t error_code,
                                    void *user_data)
{
    struct sepp_conn *conn = user_data;
    struct sepp_http2_stream *stream;

    (void)session;

    stream = http2_stream_lookup(conn->http2, stream_id);
    if (stream)
        http2_stream_free(stream);

    http2_out_body_free(http2_out_body_lookup(conn->http2, stream_id));

    SEPP_DEBUG("HTTP/2 stream %d closed on fd %d error %u",
               stream_id,
               conn->fd,
               error_code);
    return 0;
}

static int http2_set_callbacks(nghttp2_session_callbacks **callbacks)
{
    if (nghttp2_session_callbacks_new(callbacks) != 0)
        return -1;

    nghttp2_session_callbacks_set_send_callback(*callbacks, http2_send_cb);
    nghttp2_session_callbacks_set_on_begin_headers_callback(*callbacks,
                                                            http2_on_begin_headers_cb);
    nghttp2_session_callbacks_set_on_header_callback(*callbacks,
                                                     http2_on_header_cb);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(*callbacks,
                                                              http2_on_data_chunk_recv_cb);
    nghttp2_session_callbacks_set_on_frame_recv_callback(*callbacks,
                                                         http2_on_frame_recv_cb);
    nghttp2_session_callbacks_set_on_stream_close_callback(*callbacks,
                                                           http2_on_stream_close_cb);
    return 0;
}

static int http2_submit_initial_settings(struct sepp_http2 *h2)
{
    nghttp2_settings_entry iv[5];
    int rv;

    iv[0].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
    iv[0].value = SEPP_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;

    iv[1].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
    iv[1].value = SEPP_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE;

    iv[2].settings_id = NGHTTP2_SETTINGS_MAX_FRAME_SIZE;
    iv[2].value = SEPP_HTTP2_SETTINGS_MAX_FRAME_SIZE;

    iv[3].settings_id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE;
    iv[3].value = SEPP_HTTP2_SETTINGS_HEADER_TABLE_SIZE;

    iv[4].settings_id = NGHTTP2_SETTINGS_ENABLE_PUSH;
    iv[4].value = SEPP_HTTP2_SETTINGS_ENABLE_PUSH;

    rv = nghttp2_submit_settings(h2->session, NGHTTP2_FLAG_NONE, iv, 5);
    if (rv != 0) {
        SEPP_ERROR("nghttp2_submit_settings failed on fd %d: %s",
                   h2->conn->fd,
                   nghttp2_strerror(rv));
        return -1;
    }

    return 0;
}

static int http2_update_events(struct sepp_conn *conn)
{
    uint32_t events = EPOLLIN | EPOLLRDHUP;

    if (sepp_http2_want_write(conn))
        events |= EPOLLOUT;

    return event_mod(&conn->ctx->events, &conn->ev, events);
}

struct sepp_http2_stream *sepp_http2_stream_lookup(struct sepp_conn *conn,
                                                   int32_t stream_id)
{
    if (!conn || !conn->http2)
        return NULL;

    return http2_stream_lookup(conn->http2, stream_id);
}

void sepp_http2_stream_set_n32_operation(struct sepp_http2_stream *stream,
                                         enum sepp_n32_operation op)
{
    if (!stream)
        return;

    stream->n32_operation = op;
}

enum sepp_n32_operation
sepp_http2_stream_get_n32_operation(const struct sepp_http2_stream *stream)
{
    if (!stream)
        return SEPP_N32_OP_UNKNOWN;

    return stream->n32_operation;
}

int sepp_http2_expect_response(struct sepp_conn *conn,
                               int32_t stream_id,
                               enum sepp_n32_operation op)
{
    struct sepp_http2_stream *stream;

    if (!conn || !conn->http2 || stream_id <= 0 ||
        op == SEPP_N32_OP_UNKNOWN)
        return -1;

    stream = http2_stream_create(conn->http2, stream_id, 0);
    if (!stream)
        return -1;

    stream->n32_operation = op;
    return 0;
}

int sepp_http2_needs_rotation(const struct sepp_conn *conn)
{
    uint32_t next_stream_id;
    uint32_t rotate_at;

    if (!conn || !conn->http2 || conn->http2->is_server)
        return 0;

    next_stream_id = nghttp2_session_get_next_stream_id(conn->http2->session);
    rotate_at = SEPP_HTTP2_STREAM_ID_LIMIT -
                SEPP_HTTP2_STREAM_ID_ROTATION_RESERVE;

    return next_stream_id >= rotate_at;
}

static int http2_connection_names_header(
    const struct sepp_http2_header *headers,
    size_t header_count,
    const char *name)
{
    size_t i;

    if (!headers || !name)
        return 0;

    for (i = 0; i < header_count; i++) {
        const char *value;

        if (!headers[i].name || !headers[i].value ||
            strcasecmp(headers[i].name, "connection") != 0)
            continue;

        value = headers[i].value;
        while (*value != '\0') {
            const char *token;
            const char *end;

            while (*value == ' ' || *value == '\t' || *value == ',')
                value++;
            token = value;
            while (*value != '\0' && *value != ',')
                value++;
            end = value;
            while (end > token && (end[-1] == ' ' || end[-1] == '\t'))
                end--;

            if ((size_t)(end - token) == strlen(name) &&
                strncasecmp(token, name, (size_t)(end - token)) == 0)
                return 1;
        }
    }

    return 0;
}

static int http2_header_is_forwardable(
    const struct sepp_http2_header *headers,
    size_t header_count,
    const struct sepp_http2_header *header)
{
    static const char *const excluded[] = {
        "connection",
        "content-encoding",
        "content-length",
        "content-type",
        "host",
        "http2-settings",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "via",
        "3gpp-sbi-target-apiroot",
    };
    size_t i;

    if (!header || !header->name || !header->value ||
        header->name[0] == '\0' || header->name[0] == ':')
        return 0;

    for (i = 0; i < sizeof(excluded) / sizeof(excluded[0]); i++) {
        if (strcasecmp(header->name, excluded[i]) == 0)
            return 0;
    }

    return !http2_connection_names_header(headers,
                                           header_count,
                                           header->name);
}

static int http2_headers_have(const struct sepp_http2_header *headers,
                              size_t header_count,
                              const char *name)
{
    size_t i;

    if (!headers || !name)
        return 0;

    for (i = 0; i < header_count; i++) {
        if (headers[i].name && strcasecmp(headers[i].name, name) == 0 &&
            http2_header_is_forwardable(headers, header_count, &headers[i]))
            return 1;
    }

    return 0;
}

static void http2_append_forwarded_headers(
    nghttp2_nv *nva,
    size_t *nvlen,
    const struct sepp_http2_header *headers,
    size_t header_count)
{
    size_t i;

    if (!nva || !nvlen || !headers)
        return;

    for (i = 0; i < header_count; i++) {
        if (!http2_header_is_forwardable(headers, header_count, &headers[i]))
            continue;

        nva[*nvlen].name = (uint8_t *)headers[i].name;
        nva[*nvlen].value = (uint8_t *)headers[i].value;
        nva[*nvlen].namelen = strlen(headers[i].name);
        nva[*nvlen].valuelen = strlen(headers[i].value);
        nva[*nvlen].flags = NGHTTP2_NV_FLAG_NONE;
        (*nvlen)++;
    }
}

static void http2_append_via_headers(
    nghttp2_nv *nva,
    size_t *nvlen,
    const struct sepp_http2_header *headers,
    size_t header_count,
    const char *local_via)
{
    size_t i;

    if (!nva || !nvlen || !local_via || local_via[0] == '\0')
        return;

    if (headers &&
        !http2_connection_names_header(headers, header_count, "via")) {
        for (i = 0; i < header_count; i++) {
            if (!headers[i].name || !headers[i].value ||
                strcasecmp(headers[i].name, "via") != 0)
                continue;

            nva[*nvlen].name = (uint8_t *)"via";
            nva[*nvlen].value = (uint8_t *)headers[i].value;
            nva[*nvlen].namelen = sizeof("via") - 1u;
            nva[*nvlen].valuelen = strlen(headers[i].value);
            nva[*nvlen].flags = NGHTTP2_NV_FLAG_NONE;
            (*nvlen)++;
        }
    }

    nva[*nvlen].name = (uint8_t *)"via";
    nva[*nvlen].value = (uint8_t *)local_via;
    nva[*nvlen].namelen = sizeof("via") - 1u;
    nva[*nvlen].valuelen = strlen(local_via);
    nva[*nvlen].flags = NGHTTP2_NV_FLAG_NONE;
    (*nvlen)++;
}


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
                              size_t body_len)
{
    struct sepp_http2 *h2;
    struct sepp_http2_out_body *out = NULL;
    nghttp2_data_provider data_prd;
    nghttp2_data_provider *data_prd_ptr = NULL;
    nghttp2_nv *nva;
    char content_len_buf[32];
    size_t nvlen = 0;
    int32_t stream_id;

    if (!conn || !conn->http2 || !method || !scheme || !authority || !path ||
        (header_count > 0 && !headers))
        return -1;

    h2 = conn->http2;
    if (h2->is_server)
        return -1;
    if (header_count > SIZE_MAX / sizeof(*nva) - 10u)
        return -1;

    nva = calloc(header_count + 10u, sizeof(*nva));
    if (!nva)
        return -1;

    snprintf(content_len_buf, sizeof(content_len_buf), "%zu", body_len);

#define SEPP_HTTP2_NV(NAME, VALUE) \
    { (uint8_t *)(NAME), (uint8_t *)(VALUE), sizeof(NAME) - 1u, strlen(VALUE), NGHTTP2_NV_FLAG_NONE }

    nva[nvlen++] = (nghttp2_nv)SEPP_HTTP2_NV(":method", method);
    nva[nvlen++] = (nghttp2_nv)SEPP_HTTP2_NV(":scheme", scheme);
    nva[nvlen++] = (nghttp2_nv)SEPP_HTTP2_NV(":authority", authority);
    nva[nvlen++] = (nghttp2_nv)SEPP_HTTP2_NV(":path", path);
    nva[nvlen++] = (nghttp2_nv)SEPP_HTTP2_NV("content-type", content_type ? content_type : "application/json");
    nva[nvlen++] = (nghttp2_nv)SEPP_HTTP2_NV("content-length", content_len_buf);
    if (!http2_headers_have(headers, header_count, "user-agent"))
        nva[nvlen++] = (nghttp2_nv)SEPP_HTTP2_NV("user-agent", "seppd");
    if (target_api_root && target_api_root[0] != '\0')
        nva[nvlen++] = (nghttp2_nv)SEPP_HTTP2_NV("3gpp-sbi-target-apiroot", target_api_root);
    if (content_encoding && content_encoding[0] != '\0')
        nva[nvlen++] = (nghttp2_nv)SEPP_HTTP2_NV("content-encoding", content_encoding);
    http2_append_forwarded_headers(nva, &nvlen, headers, header_count);
    http2_append_via_headers(nva,
                             &nvlen,
                             headers,
                             header_count,
                             local_via);

#undef SEPP_HTTP2_NV

    if (body_len > 0) {
        if (!body)
            goto fail;

        out = calloc(1, sizeof(*out));
        if (!out)
            goto fail;
        sepp_object_counter_alloc(SEPP_OBJECT_HTTP2_OUT_BODY);

        out->data = malloc(body_len);
        if (!out->data) {
            sepp_object_counter_free(SEPP_OBJECT_HTTP2_OUT_BODY);
            free(out);
            goto fail;
        }

        memcpy(out->data, body, body_len);
        out->len = body_len;
        sepp_list_init(&out->node);

        memset(&data_prd, 0, sizeof(data_prd));
        data_prd.source.ptr = out;
        data_prd.read_callback = http2_response_read_cb;
        data_prd_ptr = &data_prd;
    }

    stream_id = nghttp2_submit_request(h2->session,
                                       NULL,
                                       nva,
                                       (size_t)nvlen,
                                       data_prd_ptr,
                                       NULL);
    free(nva);
    if (stream_id < 0) {
        SEPP_ERROR("nghttp2_submit_request failed on fd %d: %s",
                   conn->fd,
                   nghttp2_strerror(stream_id));
        http2_out_body_free(out);
        return -1;
    }

    if (out) {
        out->stream_id = stream_id;
        sepp_list_add_tail(&out->node, &h2->out_bodies);
    }

    if (sepp_http2_on_writable(conn) != 0)
        return -1;

    return stream_id;

fail:
    free(nva);
    return -1;
}

int sepp_http2_submit_response(struct sepp_conn *conn,
                               int32_t stream_id,
                               unsigned int status,
                               const char *content_type,
                               const char *content_encoding,
                               const char *local_via,
                               const struct sepp_http2_header *headers,
                               size_t header_count,
                               const unsigned char *body,
                               size_t body_len)
{
    struct sepp_http2 *h2;
    struct sepp_http2_out_body *out = NULL;
    nghttp2_data_provider data_prd;
    nghttp2_data_provider *data_prd_ptr = NULL;
    nghttp2_nv *nva;
    char status_buf[4];
    char content_len_buf[32];
    size_t nvlen = 0;
    int rv;

    if (!conn || !conn->http2 || stream_id <= 0 || status > 999u ||
        (header_count > 0 && !headers))
        return -1;

    h2 = conn->http2;
    if (!h2->is_server)
        return -1;

    if (http2_out_body_lookup(h2, stream_id))
        return -1;
    if (header_count > SIZE_MAX / sizeof(*nva) - 6u)
        return -1;

    nva = calloc(header_count + 6u, sizeof(*nva));
    if (!nva)
        return -1;

    snprintf(status_buf, sizeof(status_buf), "%03u", status);
    snprintf(content_len_buf, sizeof(content_len_buf), "%zu", body_len);

#define SEPP_HTTP2_NV(NAME, VALUE) \
    { (uint8_t *)(NAME), (uint8_t *)(VALUE), sizeof(NAME) - 1u, strlen(VALUE), NGHTTP2_NV_FLAG_NONE }

    nva[nvlen++] = (nghttp2_nv)SEPP_HTTP2_NV(":status", status_buf);
    nva[nvlen++] = (nghttp2_nv)SEPP_HTTP2_NV("content-type", content_type ? content_type : "application/json");
    nva[nvlen++] = (nghttp2_nv)SEPP_HTTP2_NV("content-length", content_len_buf);
    if (!http2_headers_have(headers, header_count, "server"))
        nva[nvlen++] = (nghttp2_nv)SEPP_HTTP2_NV("server", "seppd");
    if (content_encoding && content_encoding[0] != '\0')
        nva[nvlen++] = (nghttp2_nv)SEPP_HTTP2_NV("content-encoding", content_encoding);
    http2_append_forwarded_headers(nva, &nvlen, headers, header_count);
    http2_append_via_headers(nva,
                             &nvlen,
                             headers,
                             header_count,
                             local_via);

#undef SEPP_HTTP2_NV

    if (body_len > 0) {
        if (!body)
            goto fail;

        out = calloc(1, sizeof(*out));
        if (!out)
            goto fail;
        sepp_object_counter_alloc(SEPP_OBJECT_HTTP2_OUT_BODY);

        out->data = malloc(body_len);
        if (!out->data) {
            sepp_object_counter_free(SEPP_OBJECT_HTTP2_OUT_BODY);
            free(out);
            goto fail;
        }

        memcpy(out->data, body, body_len);
        out->len = body_len;
        out->stream_id = stream_id;
        sepp_list_init(&out->node);
        sepp_list_add_tail(&out->node, &h2->out_bodies);

        memset(&data_prd, 0, sizeof(data_prd));
        data_prd.source.ptr = out;
        data_prd.read_callback = http2_response_read_cb;
        data_prd_ptr = &data_prd;
    }

    rv = nghttp2_submit_response(h2->session,
                                 stream_id,
                                 nva,
                                 nvlen,
                                 data_prd_ptr);
    free(nva);
    if (rv != 0) {
        SEPP_ERROR("nghttp2_submit_response failed on fd %d stream %d: %s",
                   conn->fd,
                   stream_id,
                   nghttp2_strerror(rv));
        http2_out_body_free(out);
        return -1;
    }

    if (sepp_http2_on_writable(conn) != 0)
        return -1;

    return 0;

fail:
    free(nva);
    return -1;
}

int sepp_http2_start(struct sepp_conn *conn, int is_server)
{
    nghttp2_session_callbacks *callbacks = NULL;
    struct sepp_http2 *h2;
    size_t i;
    int rv;

    if (!conn)
        return -1;

    if (conn->http2)
        return 0;

    h2 = calloc(1, sizeof(*h2));
    if (!h2)
        return -1;
    sepp_object_counter_alloc(SEPP_OBJECT_HTTP2_SESSION);

    h2->conn = conn;
    h2->is_server = is_server;
    for (i = 0; i < SEPP_HTTP2_STREAM_BUCKETS; i++)
        sepp_list_init(&h2->stream_buckets[i]);
    sepp_list_init(&h2->out_bodies);

    if (http2_set_callbacks(&callbacks) != 0) {
        sepp_object_counter_free(SEPP_OBJECT_HTTP2_SESSION);
        free(h2);
        return -1;
    }

    if (is_server)
        rv = nghttp2_session_server_new(&h2->session, callbacks, conn);
    else
        rv = nghttp2_session_client_new(&h2->session, callbacks, conn);

    nghttp2_session_callbacks_del(callbacks);

    if (rv != 0) {
        SEPP_ERROR("nghttp2_session_new failed on fd %d: %s",
                   conn->fd,
                   nghttp2_strerror(rv));
        sepp_object_counter_free(SEPP_OBJECT_HTTP2_SESSION);
        free(h2);
        return -1;
    }

    conn->http2 = h2;

    if (http2_submit_initial_settings(h2) != 0) {
        sepp_http2_destroy(conn);
        return -1;
    }

    if (sepp_http2_on_writable(conn) != 0) {
        sepp_http2_destroy(conn);
        return -1;
    }

    if (http2_update_events(conn) != 0) {
        sepp_http2_destroy(conn);
        return -1;
    }

    SEPP_INFO("HTTP/2 %s session started on fd %d",
              is_server ? "server" : "client",
              conn->fd);
    return 0;
}

void sepp_http2_destroy(struct sepp_conn *conn)
{
    struct sepp_http2 *h2;
    size_t i;

    if (!conn || !conn->http2)
        return;

    h2 = conn->http2;
    conn->http2 = NULL;

    for (i = 0; i < SEPP_HTTP2_STREAM_BUCKETS; i++) {
        struct sepp_list *head = &h2->stream_buckets[i];
        struct sepp_list *pos;
        struct sepp_list *next;

        sepp_list_for_each_safe(pos, next, head) {
            struct sepp_http2_stream *stream;

            stream = sepp_list_entry(pos, struct sepp_http2_stream, hash_node);
            http2_stream_free(stream);
        }
    }

    while (!sepp_list_empty(&h2->out_bodies)) {
        struct sepp_http2_out_body *body;

        body = sepp_list_first_entry(&h2->out_bodies,
                                     struct sepp_http2_out_body,
                                     node);
        http2_out_body_free(body);
    }

    if (h2->session)
        nghttp2_session_del(h2->session);

    sepp_object_counter_free(SEPP_OBJECT_HTTP2_SESSION);
    free(h2);
}

int sepp_http2_set_msg_cb(struct sepp_conn *conn,
                          sepp_http2_msg_cb cb,
                          void *arg)
{
    if (!conn || !conn->http2)
        return -1;

    conn->http2->msg_cb = cb;
    conn->http2->msg_arg = arg;

    return 0;
}

int sepp_http2_on_readable(struct sepp_conn *conn)
{
    uint8_t buf[SEPP_HTTP2_READ_BUF_SIZE];
    struct sepp_http2 *h2;

    if (!conn || !conn->http2)
        return -1;

    h2 = conn->http2;

    for (;;) {
        ssize_t nread;
        ssize_t nparsed;

        nread = sepp_channel_read(conn, buf, sizeof(buf));
        if (nread > 0) {
            nparsed = nghttp2_session_mem_recv(h2->session, buf, (size_t)nread);
            if (nparsed < 0) {
                SEPP_ERROR("nghttp2_session_mem_recv failed on fd %d: %s",
                           conn->fd,
                           nghttp2_strerror((int)nparsed));
                return -1;
            }

            if (nparsed != nread) {
                SEPP_ERROR("HTTP/2 parser consumed %zd of %zd bytes on fd %d",
                           nparsed,
                           nread,
                           conn->fd);
                return -1;
            }

            if (sepp_http2_on_writable(conn) != 0)
                return -1;

            continue;
        }

        if (nread == 0) {
            SEPP_INFO("HTTP/2 fd %d closed by peer", conn->fd);
            return -1;
        }

        if (errno == EAGAIN || errno == EWOULDBLOCK)
            break;

        if (errno == EINTR)
            continue;

        SEPP_ERROR("HTTP/2 read on fd %d failed: %s",
                   conn->fd,
                   strerror(errno));
        return -1;
    }

    return http2_update_events(conn);
}

int sepp_http2_on_writable(struct sepp_conn *conn)
{
    struct sepp_http2 *h2;
    int rv;

    if (!conn || !conn->http2)
        return -1;

    h2 = conn->http2;
    rv = nghttp2_session_send(h2->session);
    if (rv != 0) {
        SEPP_ERROR("nghttp2_session_send failed on fd %d: %s",
                   conn->fd,
                   nghttp2_strerror(rv));
        return -1;
    }

    return http2_update_events(conn);
}

int sepp_http2_want_write(const struct sepp_conn *conn)
{
    if (!conn || !conn->http2)
        return 0;

    return nghttp2_session_want_write(conn->http2->session) != 0;
}
