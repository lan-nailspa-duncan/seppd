#ifndef ROUTING_H
#define ROUTING_H

#include <stddef.h>
#include <stdint.h>

#include "config.h"
#include "target.h"

struct sepp_context;

int sepp_routing_parse_api_root(const char *api_root,
                                char *fqdn,
                                size_t fqdn_len,
                                uint16_t *port);

int sepp_routing_peer_from_api_root(struct sepp_context *ctx,
                                    const char *api_root,
                                    struct sepp_target_key *key,
                                    const struct sepp_target_config **cfg);

int sepp_routing_internal_from_api_root(struct sepp_context *ctx,
                                        const char *api_root,
                                        struct sepp_target_key *key,
                                        const struct sepp_target_config **cfg,
                                        int *preserve_target_api_root);

#endif /* ROUTING_H */
