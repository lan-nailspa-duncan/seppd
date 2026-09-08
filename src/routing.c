#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "config.h"
#include "log.h"
#include "routing.h"
#include "sepp.h"
#include "target.h"

#define ROUTING_SCHEME_HTTPS "https://"
#define ROUTING_SCHEME_HTTP  "http://"
#define ROUTING_DEFAULT_HTTPS_PORT 443u
#define ROUTING_DEFAULT_HTTP_PORT  80u

int sepp_routing_parse_api_root(const char *api_root,
                                char *fqdn,
                                size_t fqdn_len,
                                uint16_t *port)
{
    const char *host;
    const char *end;
    const char *colon;
    unsigned int parsed_port;
    size_t scheme_len;
    size_t host_len;

    if (!api_root || !fqdn || fqdn_len == 0 || !port)
        return -1;

    /* Real deployments (e.g. open5gs) use the target NF's own internal
     * scheme in 3gpp-Sbi-Target-apiRoot, which is commonly plain HTTP for
     * intra-PLMN calls, regardless of the TLS-protected N32-f transport
     * this value travels over. Accept both; the outbound connection to
     * the resolved target is always made over TLS by the connector
     * (see connector.c), so this does not weaken transport security. */
    if (strncmp(api_root,
                ROUTING_SCHEME_HTTPS,
                sizeof(ROUTING_SCHEME_HTTPS) - 1u) == 0) {
        scheme_len = sizeof(ROUTING_SCHEME_HTTPS) - 1u;
        parsed_port = ROUTING_DEFAULT_HTTPS_PORT;
    } else if (strncmp(api_root,
                       ROUTING_SCHEME_HTTP,
                       sizeof(ROUTING_SCHEME_HTTP) - 1u) == 0) {
        scheme_len = sizeof(ROUTING_SCHEME_HTTP) - 1u;
        parsed_port = ROUTING_DEFAULT_HTTP_PORT;
    } else {
        return -1;
    }

    host = api_root + scheme_len;
    if (*host == '\0')
        return -1;

    end = strchr(host, '/');
    if (!end)
        end = host + strlen(host);

    colon = memchr(host, ':', (size_t)(end - host));
    if (colon) {
        char port_buf[8];
        size_t port_len = (size_t)(end - colon - 1);

        if (port_len == 0 || port_len >= sizeof(port_buf))
            return -1;

        memcpy(port_buf, colon + 1, port_len);
        port_buf[port_len] = '\0';

        if (sscanf(port_buf, "%u", &parsed_port) != 1 ||
            parsed_port == 0 || parsed_port > UINT16_MAX)
            return -1;

        host_len = (size_t)(colon - host);
    } else {
        host_len = (size_t)(end - host);
    }

    if (host_len == 0 || host_len >= fqdn_len)
        return -1;

    memcpy(fqdn, host, host_len);
    fqdn[host_len] = '\0';
    *port = (uint16_t)parsed_port;

    return 0;
}

static int routing_domain_matches(const char *fqdn, const char *pattern)
{
    size_t fqdn_len;
    size_t suffix_len;

    if (!fqdn || !pattern || pattern[0] == '\0')
        return 0;

    if (strncmp(pattern, "*.", 2) != 0)
        return strcasecmp(fqdn, pattern) == 0;

    fqdn_len = strlen(fqdn);
    suffix_len = strlen(pattern + 1);
    if (fqdn_len <= suffix_len)
        return 0;

    return strcasecmp(fqdn + fqdn_len - suffix_len, pattern + 1) == 0;
}

int sepp_routing_peer_from_api_root(struct sepp_context *ctx,
                                    const char *api_root,
                                    struct sepp_target_key *key,
                                    const struct sepp_target_config **cfg)
{
    const struct sepp_target_config *match = NULL;
    char fqdn[SEPP_CONFIG_FQDN_LEN];
    uint16_t port;

    if (!ctx || !key ||
        sepp_routing_parse_api_root(api_root, fqdn, sizeof(fqdn), &port) != 0)
        return -1;

    (void)port;
    for (int i = 0; i < ctx->config.target_count; i++) {
        const struct sepp_target_config *candidate = &ctx->config.targets[i];

        if (candidate->type != SEPP_TARGET_PEER_SEPP)
            continue;

        for (int j = 0; j < candidate->served_domain_count; j++) {
            if (!routing_domain_matches(fqdn, candidate->served_domains[j]))
                continue;
            if (match && match != candidate) {
                SEPP_ERROR("ambiguous peer route for target apiRoot %s", api_root);
                return -1;
            }
            match = candidate;
        }
    }

    if (!match) {
        SEPP_ERROR("no configured peer domain route for apiRoot %s", api_root);
        return -1;
    }

    if (sepp_target_from_config(match, key) != 0)
        return -1;
    if (cfg)
        *cfg = match;
    return 0;
}

int sepp_routing_internal_from_api_root(struct sepp_context *ctx,
                                        const char *api_root,
                                        struct sepp_target_key *key,
                                        const struct sepp_target_config **cfg,
                                        int *preserve_target_api_root)
{
    char fqdn[SEPP_CONFIG_FQDN_LEN];
    uint16_t port;

    if (!ctx || !key || !preserve_target_api_root ||
        sepp_routing_parse_api_root(api_root, fqdn, sizeof(fqdn), &port) != 0)
        return -1;

    if (ctx->config.internal_route_mode == SEPP_INTERNAL_ROUTE_SCP) {
        int allowed = 0;

        for (int i = 0; i < ctx->config.internal_served_domain_count; i++) {
            if (routing_domain_matches(
                    fqdn, ctx->config.internal_served_domains[i])) {
                allowed = 1;
                break;
            }
        }
        if (!allowed) {
            SEPP_ERROR("target apiRoot is outside configured local domains: %s",
                       api_root);
            return -1;
        }

        for (int i = 0; i < ctx->config.target_count; i++) {
            const struct sepp_target_config *candidate = &ctx->config.targets[i];

            if (candidate->type != SEPP_TARGET_SCP ||
                strcmp(candidate->name, ctx->config.internal_scp) != 0)
                continue;
            if (sepp_target_from_config(candidate, key) != 0)
                return -1;
            if (cfg)
                *cfg = candidate;
            *preserve_target_api_root = 1;
            return 0;
        }
        SEPP_ERROR("configured internal SCP target %s is unavailable",
                   ctx->config.internal_scp);
        return -1;
    }

    SEPP_DEBUG("routing: direct-mode lookup for apiRoot=%s (parsed fqdn=%s port=%u)",
               api_root, fqdn, (unsigned int)port);

    for (int i = 0; i < ctx->config.target_count; i++) {
        const struct sepp_target_config *candidate = &ctx->config.targets[i];

        if (candidate->type != SEPP_TARGET_INTERNAL_NF ||
            candidate->port != port || strcasecmp(candidate->fqdn, fqdn) != 0)
            continue;
        SEPP_DEBUG("routing: matched direct internal NF target name=%s fqdn=%s:%u",
                   candidate->name, candidate->fqdn, (unsigned int)candidate->port);
        if (sepp_target_from_config(candidate, key) != 0)
            return -1;
        if (cfg)
            *cfg = candidate;
        *preserve_target_api_root = 0;
        return 0;
    }

    SEPP_ERROR("no configured direct internal NF for apiRoot %s", api_root);
    return -1;
}
