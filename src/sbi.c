#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "sbi.h"

#define SBI_HDR_TARGET_API_ROOT "3gpp-sbi-target-apiroot"
#define SBI_HDR_CALLBACK        "3gpp-sbi-callback"
#define SBI_HDR_CORRELATION     "3gpp-sbi-correlation-info"
#define SBI_HDR_VIA             "via"
#define SBI_VIA_SEPP_PREFIX     "SEPP-"

static void sbi_copy_value(char *dst, size_t dst_len, const char *value)
{
    if (!dst || dst_len == 0)
        return;

    dst[0] = '\0';

    if (!value)
        return;

    snprintf(dst, dst_len, "%s", value);
}

void sepp_sbi_headers_clear(struct sepp_sbi_headers *sbi)
{
    if (!sbi)
        return;

    sbi->target_api_root[0] = '\0';
    sbi->callback[0] = '\0';
    sbi->correlation_info[0] = '\0';
}

void sepp_sbi_headers_parse(struct sepp_sbi_headers *sbi,
                            const struct sepp_http2_header *headers,
                            size_t header_count)
{
    size_t i;

    if (!sbi)
        return;

    sepp_sbi_headers_clear(sbi);

    if (!headers)
        return;

    for (i = 0; i < header_count; i++) {
        const char *name = headers[i].name;
        const char *value = headers[i].value;

        if (!name || !value)
            continue;

        if (strcasecmp(name, SBI_HDR_TARGET_API_ROOT) == 0) {
            sbi_copy_value(sbi->target_api_root,
                           sizeof(sbi->target_api_root),
                           value);
        } else if (strcasecmp(name, SBI_HDR_CALLBACK) == 0) {
            sbi_copy_value(sbi->callback,
                           sizeof(sbi->callback),
                           value);
        } else if (strcasecmp(name, SBI_HDR_CORRELATION) == 0) {
            sbi_copy_value(sbi->correlation_info,
                           sizeof(sbi->correlation_info),
                           value);
        }
    }
}

static int sbi_is_ows(char ch)
{
    return ch == ' ' || ch == '\t';
}

static int sbi_via_entry_has_sepp_fqdn(const char *entry,
                                       size_t entry_len,
                                       const char *fqdn)
{
    const char *p;
    const char *end;
    const char *received_by;
    size_t received_by_len;
    size_t prefix_len = sizeof(SBI_VIA_SEPP_PREFIX) - 1u;
    size_t fqdn_len;

    if (!entry || !fqdn || fqdn[0] == '\0')
        return 0;

    p = entry;
    end = entry + entry_len;
    while (p < end && sbi_is_ows(*p))
        p++;

    /* Skip received-protocol.  Via requires RWS between received-protocol
     * and received-by. */
    while (p < end && !sbi_is_ows(*p))
        p++;
    if (p == end)
        return 0;

    while (p < end && sbi_is_ows(*p))
        p++;
    if (p == end)
        return 0;

    received_by = p;
    while (p < end && !sbi_is_ows(*p) && *p != '(')
        p++;
    received_by_len = (size_t)(p - received_by);

    fqdn_len = strlen(fqdn);
    if (received_by_len != prefix_len + fqdn_len)
        return 0;

    if (strncasecmp(received_by,
                    SBI_VIA_SEPP_PREFIX,
                    prefix_len) != 0)
        return 0;

    return strncasecmp(received_by + prefix_len, fqdn, fqdn_len) == 0;
}

static int sbi_via_value_has_sepp_fqdn(const char *value,
                                       const char *fqdn)
{
    const char *p;

    if (!value || !fqdn)
        return 0;

    p = value;
    while (*p != '\0') {
        const char *entry;
        const char *end;
        unsigned int comment_depth = 0;

        while (*p == ',' || sbi_is_ows(*p))
            p++;
        if (*p == '\0')
            break;

        entry = p;
        while (*p != '\0') {
            if (comment_depth > 0 && *p == '\\' && p[1] != '\0') {
                p += 2;
                continue;
            }

            if (*p == '(') {
                comment_depth++;
            } else if (*p == ')' && comment_depth > 0) {
                comment_depth--;
            } else if (*p == ',' && comment_depth == 0) {
                break;
            }
            p++;
        }

        end = p;
        while (end > entry && sbi_is_ows(end[-1]))
            end--;

        if (sbi_via_entry_has_sepp_fqdn(entry,
                                        (size_t)(end - entry),
                                        fqdn))
            return 1;

        if (*p == ',')
            p++;
    }

    return 0;
}

int sepp_sbi_via_has_sepp_fqdn(const struct sepp_http2_header *headers,
                               size_t header_count,
                               const char *fqdn)
{
    if (!headers || !fqdn || fqdn[0] == '\0')
        return 0;

    for (size_t i = 0; i < header_count; i++) {
        if (!headers[i].name || !headers[i].value)
            continue;

        if (strcasecmp(headers[i].name, SBI_HDR_VIA) == 0 &&
            sbi_via_value_has_sepp_fqdn(headers[i].value, fqdn))
            return 1;
    }

    return 0;
}
