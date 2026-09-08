#ifndef SEPP_MIME_H
#define SEPP_MIME_H

#include <stddef.h>
#include <stdint.h>

#define SEPP_MIME_BOUNDARY_MAX     70u
#define SEPP_MIME_PARTS_MAX        64u
#define SEPP_MIME_HEADERS_MAX      64u
#define SEPP_MIME_HEADER_BYTES_MAX 65536u

struct sepp_mime_header {
    char *name;
    char *value;
};

struct sepp_mime_part {
    struct sepp_mime_header *headers;
    size_t header_count;

    const uint8_t *body;
    size_t body_len;

    const char *content_type;
    const char *content_id;
};

struct sepp_multipart {
    struct sepp_mime_part *parts;
    size_t part_count;
};

/* Return 1 for a parsed multipart representation, 0 when Content-Type is not
 * multipart, and -1 for a malformed multipart representation. */
int sepp_multipart_parse(struct sepp_multipart *multipart,
                         const char *content_type,
                         const uint8_t *body,
                         size_t body_len);

void sepp_multipart_cleanup(struct sepp_multipart *multipart);

const char *sepp_mime_part_find_header(const struct sepp_mime_part *part,
                                       const char *name);

/* Recognizes application/json and application media types with a +json
 * structured syntax suffix, ignoring media-type parameters. */
int sepp_mime_content_type_is_json(const char *content_type);
int sepp_mime_part_is_json(const struct sepp_mime_part *part);

#endif /* SEPP_MIME_H */
