#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "mime.h"
#include "object_counter.h"

#define SEPP_MIME_PARAMETER_MAX 1024u

static int mime_is_ows(char ch)
{
    return ch == ' ' || ch == '\t';
}

static int mime_is_token_char(unsigned char ch)
{
    if (ch == '\0')
        return 0;

    if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
        (ch >= '0' && ch <= '9'))
        return 1;

    return strchr("!#$%&'*+-.^_`|~", ch) != NULL;
}

static int mime_boundary_char_valid(unsigned char ch)
{
    if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
        (ch >= '0' && ch <= '9') || ch == ' ')
        return 1;

    return strchr("'()+_,-./:=?", ch) != NULL;
}

static int mime_boundary_valid(const char *boundary, size_t len)
{
    size_t i;

    if (!boundary || len == 0 || len > SEPP_MIME_BOUNDARY_MAX ||
        boundary[len - 1u] == ' ')
        return 0;

    for (i = 0; i < len; i++) {
        if (!mime_boundary_char_valid((unsigned char)boundary[i]))
            return 0;
    }

    return 1;
}

static int mime_copy_parameter_value(const char **cursor,
                                     char *value,
                                     size_t value_len,
                                     size_t *copied_len)
{
    const char *p = *cursor;
    size_t len = 0;

    if (*p == '"') {
        p++;
        while (*p != '\0' && *p != '"') {
            unsigned char ch = (unsigned char)*p++;

            if (ch == '\\') {
                if (*p == '\0')
                    return -1;
                ch = (unsigned char)*p++;
            }
            if (ch == '\r' || ch == '\n' || len + 1u >= value_len)
                return -1;
            value[len++] = (char)ch;
        }
        if (*p != '"')
            return -1;
        p++;
    } else {
        const char *start = p;

        while (*p != '\0' && *p != ';' && !mime_is_ows(*p)) {
            if (!mime_is_token_char((unsigned char)*p))
                return -1;
            p++;
        }
        len = (size_t)(p - start);
        if (len == 0 || len + 1u > value_len)
            return -1;
        memcpy(value, start, len);
    }

    value[len] = '\0';
    *cursor = p;
    *copied_len = len;
    return 0;
}

static int mime_parse_boundary_parameter(const char *content_type,
                                         char *boundary,
                                         size_t boundary_len,
                                         size_t *parsed_len)
{
    const char *p;
    const char *type_start;
    const char *type_end;
    int boundary_seen = 0;

    if (!content_type || !boundary || !parsed_len)
        return -1;

    p = content_type;
    while (mime_is_ows(*p))
        p++;
    type_start = p;
    while (*p != '\0' && *p != ';' && !mime_is_ows(*p))
        p++;
    type_end = p;
    if ((size_t)(type_end - type_start) < sizeof("multipart/") - 1u ||
        strncasecmp(type_start,
                    "multipart/",
                    sizeof("multipart/") - 1u) != 0)
        return 0;
    if ((size_t)(type_end - type_start) == sizeof("multipart/") - 1u)
        return -1;
    for (const char *subtype = type_start + sizeof("multipart/") - 1u;
         subtype < type_end;
         subtype++) {
        if (!mime_is_token_char((unsigned char)*subtype))
            return -1;
    }

    while (mime_is_ows(*p))
        p++;

    while (*p != '\0') {
        const char *name;
        size_t name_len;
        char parameter[SEPP_MIME_PARAMETER_MAX + 1u];
        size_t parameter_len;

        if (*p++ != ';')
            return -1;
        while (mime_is_ows(*p))
            p++;

        name = p;
        while (mime_is_token_char((unsigned char)*p))
            p++;
        name_len = (size_t)(p - name);
        if (name_len == 0)
            return -1;

        while (mime_is_ows(*p))
            p++;
        if (*p++ != '=')
            return -1;
        while (mime_is_ows(*p))
            p++;

        if (mime_copy_parameter_value(&p,
                                      parameter,
                                      sizeof(parameter),
                                      &parameter_len) != 0)
            return -1;
        while (mime_is_ows(*p))
            p++;
        if (*p != '\0' && *p != ';')
            return -1;

        if (name_len == sizeof("boundary") - 1u &&
            strncasecmp(name, "boundary", name_len) == 0) {
            if (boundary_seen ||
                !mime_boundary_valid(parameter, parameter_len) ||
                parameter_len + 1u > boundary_len)
                return -1;

            memcpy(boundary, parameter, parameter_len + 1u);
            *parsed_len = parameter_len;
            boundary_seen = 1;
        }
    }

    return boundary_seen ? 1 : -1;
}

static int mime_match_delimiter(const uint8_t *body,
                                size_t body_len,
                                size_t pos,
                                const char *boundary,
                                size_t boundary_len,
                                int *closing,
                                size_t *after)
{
    size_t p;

    if (!body || !boundary || !closing || !after ||
        (pos != 0 && (pos < 2 || body[pos - 2] != '\r' ||
                      body[pos - 1] != '\n')) ||
        body_len - pos < boundary_len + 2u || body[pos] != '-' ||
        body[pos + 1u] != '-' ||
        memcmp(body + pos + 2u, boundary, boundary_len) != 0)
        return 0;

    p = pos + 2u + boundary_len;
    *closing = 0;
    if (body_len - p >= 2u && body[p] == '-' && body[p + 1u] == '-') {
        *closing = 1;
        p += 2u;
    }

    while (p < body_len && (body[p] == ' ' || body[p] == '\t'))
        p++;

    if (p == body_len) {
        if (!*closing)
            return 0;
        *after = p;
        return 1;
    }

    if (body_len - p < 2u || body[p] != '\r' || body[p + 1u] != '\n')
        return 0;

    *after = p + 2u;
    return 1;
}

static int mime_find_delimiter(const uint8_t *body,
                               size_t body_len,
                               size_t start,
                               const char *boundary,
                               size_t boundary_len,
                               size_t *position,
                               int *closing,
                               size_t *after)
{
    size_t pos;

    for (pos = start; pos < body_len; pos++) {
        if (body[pos] != '-' ||
            (pos != 0 && (pos < 2 || body[pos - 2] != '\r' ||
                          body[pos - 1] != '\n')))
            continue;

        if (mime_match_delimiter(body,
                                 body_len,
                                 pos,
                                 boundary,
                                 boundary_len,
                                 closing,
                                 after)) {
            *position = pos;
            return 1;
        }
    }

    return 0;
}

static char *mime_copy_text(const uint8_t *text, size_t len)
{
    char *copy;

    copy = malloc(len + 1u);
    if (!copy)
        return NULL;
    memcpy(copy, text, len);
    copy[len] = '\0';
    return copy;
}

static int mime_header_name_valid(const uint8_t *name, size_t len)
{
    size_t i;

    if (!name || len == 0)
        return 0;
    for (i = 0; i < len; i++) {
        if (!mime_is_token_char(name[i]))
            return 0;
    }
    return 1;
}

static int mime_part_append_header(struct sepp_mime_part *part,
                                   const uint8_t *name,
                                   size_t name_len,
                                   const uint8_t *value,
                                   size_t value_len)
{
    struct sepp_mime_header *headers;
    char *name_copy;
    char *value_copy;

    if (!part || part->header_count >= SEPP_MIME_HEADERS_MAX)
        return -1;

    headers = realloc(part->headers,
                      (part->header_count + 1u) * sizeof(*headers));
    if (!headers)
        return -1;
    part->headers = headers;

    name_copy = mime_copy_text(name, name_len);
    if (!name_copy)
        return -1;
    value_copy = mime_copy_text(value, value_len);
    if (!value_copy) {
        free(name_copy);
        return -1;
    }

    part->headers[part->header_count].name = name_copy;
    part->headers[part->header_count].value = value_copy;
    part->header_count++;
    sepp_object_counter_alloc(SEPP_OBJECT_MIME_HEADER);
    return 0;
}

static int mime_parse_part_headers(struct sepp_mime_part *part,
                                   const uint8_t *body,
                                   size_t body_len,
                                   size_t *cursor)
{
    size_t header_bytes = 0;

    while (*cursor < body_len) {
        size_t line_start = *cursor;
        size_t line_end = line_start;
        size_t colon;
        size_t value_start;
        size_t value_end;

        while (line_end + 1u < body_len &&
               (body[line_end] != '\r' || body[line_end + 1u] != '\n'))
            line_end++;
        if (line_end + 1u >= body_len)
            return -1;

        header_bytes += line_end + 2u - line_start;
        if (header_bytes > SEPP_MIME_HEADER_BYTES_MAX)
            return -1;

        *cursor = line_end + 2u;
        if (line_end == line_start)
            return 0;

        /* Obsolete folded fields are rejected to avoid ambiguous security
         * processing.  5G SBI multipart producers use one field per line. */
        if (body[line_start] == ' ' || body[line_start] == '\t')
            return -1;

        colon = line_start;
        while (colon < line_end && body[colon] != ':')
            colon++;
        if (colon == line_end ||
            !mime_header_name_valid(body + line_start, colon - line_start))
            return -1;

        value_start = colon + 1u;
        while (value_start < line_end &&
               (body[value_start] == ' ' || body[value_start] == '\t'))
            value_start++;
        value_end = line_end;
        while (value_end > value_start &&
               (body[value_end - 1u] == ' ' || body[value_end - 1u] == '\t'))
            value_end--;

        if (mime_part_append_header(part,
                                    body + line_start,
                                    colon - line_start,
                                    body + value_start,
                                    value_end - value_start) != 0)
            return -1;
    }

    return -1;
}

const char *sepp_mime_part_find_header(const struct sepp_mime_part *part,
                                       const char *name)
{
    size_t i;

    if (!part || !name)
        return NULL;
    for (i = 0; i < part->header_count; i++) {
        if (part->headers[i].name &&
            strcasecmp(part->headers[i].name, name) == 0)
            return part->headers[i].value;
    }
    return NULL;
}

static void mime_part_cache_headers(struct sepp_mime_part *part)
{
    part->content_type = sepp_mime_part_find_header(part, "content-type");
    part->content_id = sepp_mime_part_find_header(part, "content-id");
}

int sepp_mime_content_type_is_json(const char *content_type)
{
    const char *start;
    const char *end;
    const char *slash;
    size_t subtype_len;

    if (!content_type)
        return 0;

    start = content_type;
    while (mime_is_ows(*start))
        start++;
    end = start;
    while (*end != '\0' && *end != ';' && !mime_is_ows(*end))
        end++;

    slash = memchr(start, '/', (size_t)(end - start));
    if (!slash || (size_t)(slash - start) != sizeof("application") - 1u ||
        strncasecmp(start, "application", sizeof("application") - 1u) != 0)
        return 0;

    slash++;
    subtype_len = (size_t)(end - slash);
    if (subtype_len == sizeof("json") - 1u &&
        strncasecmp(slash, "json", subtype_len) == 0)
        return 1;

    return subtype_len > sizeof("+json") - 1u &&
           strncasecmp(end - (sizeof("+json") - 1u),
                       "+json",
                       sizeof("+json") - 1u) == 0;
}

int sepp_mime_part_is_json(const struct sepp_mime_part *part)
{
    return part && sepp_mime_content_type_is_json(part->content_type);
}

void sepp_multipart_cleanup(struct sepp_multipart *multipart)
{
    size_t i;

    if (!multipart)
        return;

    for (i = 0; i < multipart->part_count; i++) {
        struct sepp_mime_part *part = &multipart->parts[i];
        size_t j;

        for (j = 0; j < part->header_count; j++) {
            free(part->headers[j].name);
            free(part->headers[j].value);
            sepp_object_counter_free(SEPP_OBJECT_MIME_HEADER);
        }
        free(part->headers);
        sepp_object_counter_free(SEPP_OBJECT_MIME_PART);
    }
    free(multipart->parts);
    memset(multipart, 0, sizeof(*multipart));
}

int sepp_multipart_parse(struct sepp_multipart *multipart,
                         const char *content_type,
                         const uint8_t *body,
                         size_t body_len)
{
    char boundary[SEPP_MIME_BOUNDARY_MAX + 1u];
    size_t boundary_len = 0;
    size_t delimiter_pos;
    size_t cursor;
    int closing;
    int type_rc;

    if (!multipart)
        return -1;
    memset(multipart, 0, sizeof(*multipart));

    type_rc = mime_parse_boundary_parameter(content_type,
                                            boundary,
                                            sizeof(boundary),
                                            &boundary_len);
    if (type_rc <= 0)
        return type_rc;
    if (!body || body_len == 0)
        return -1;

    if (!mime_find_delimiter(body,
                             body_len,
                             0,
                             boundary,
                             boundary_len,
                             &delimiter_pos,
                             &closing,
                             &cursor) || closing)
        return -1;

    for (;;) {
        struct sepp_mime_part *parts;
        struct sepp_mime_part *part;
        size_t body_start;
        size_t body_end;
        size_t next_after;

        if (multipart->part_count >= SEPP_MIME_PARTS_MAX)
            goto fail;

        parts = realloc(multipart->parts,
                        (multipart->part_count + 1u) * sizeof(*parts));
        if (!parts)
            goto fail;
        multipart->parts = parts;
        part = &multipart->parts[multipart->part_count];
        memset(part, 0, sizeof(*part));
        multipart->part_count++;
        sepp_object_counter_alloc(SEPP_OBJECT_MIME_PART);

        if (mime_parse_part_headers(part, body, body_len, &cursor) != 0)
            goto fail;
        body_start = cursor;

        if (!mime_find_delimiter(body,
                                 body_len,
                                 body_start,
                                 boundary,
                                 boundary_len,
                                 &delimiter_pos,
                                 &closing,
                                 &next_after))
            goto fail;

        if (delimiter_pos == body_start) {
            body_end = body_start;
        } else {
            if (delimiter_pos < body_start + 2u ||
                body[delimiter_pos - 2u] != '\r' ||
                body[delimiter_pos - 1u] != '\n')
                goto fail;
            body_end = delimiter_pos - 2u;
        }

        part->body = body + body_start;
        part->body_len = body_end - body_start;
        mime_part_cache_headers(part);

        if (closing)
            return 1;
        cursor = next_after;
    }

fail:
    sepp_multipart_cleanup(multipart);
    return -1;
}
