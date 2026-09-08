#ifndef SEPP_SBI_H
#define SEPP_SBI_H

#include <stddef.h>

#include "http2.h"

#define SEPP_SBI_TARGET_API_ROOT_MAX 512
#define SEPP_SBI_CALLBACK_MAX        512
#define SEPP_SBI_CORRELATION_MAX     256

struct sepp_sbi_headers {
    char target_api_root[SEPP_SBI_TARGET_API_ROOT_MAX];
    char callback[SEPP_SBI_CALLBACK_MAX];
    char correlation_info[SEPP_SBI_CORRELATION_MAX];
};

void sepp_sbi_headers_clear(struct sepp_sbi_headers *sbi);

void sepp_sbi_headers_parse(struct sepp_sbi_headers *sbi,
                            const struct sepp_http2_header *headers,
                            size_t header_count);

int sepp_sbi_via_has_sepp_fqdn(const struct sepp_http2_header *headers,
                               size_t header_count,
                               const char *fqdn);

#endif /* SEPP_SBI_H */
