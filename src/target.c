#include <stdio.h>
#include <string.h>

#include "config.h"
#include "target.h"

static unsigned int target_hash_bytes(const unsigned char *data, size_t len)
{
    unsigned int hash = 2166136261u;

    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 16777619u;
    }

    return hash;
}

unsigned int sepp_target_hash(const struct sepp_target_key *key)
{
    unsigned int hash;

    if (!key)
        return 0;

    hash = target_hash_bytes((const unsigned char *)&key->type,
                             sizeof(key->type));
    hash ^= target_hash_bytes((const unsigned char *)key->fqdn,
                              strnlen(key->fqdn, sizeof(key->fqdn))) +
            0x9e3779b9u + (hash << 6) + (hash >> 2);

    return hash;
}

int sepp_target_equal(const struct sepp_target_key *a,
                      const struct sepp_target_key *b)
{
    if (!a || !b)
        return 0;

    if (a->type != b->type)
        return 0;

    if (strncmp(a->fqdn, b->fqdn, sizeof(a->fqdn)) != 0)
        return 0;

    return 1;
}

int sepp_target_from_config(const struct sepp_target_config *cfg,
                            struct sepp_target_key *key)
{
    if (!cfg || !key)
        return -1;

    if (cfg->type == SEPP_TARGET_NONE || cfg->fqdn[0] == '\0' || cfg->port == 0)
        return -1;

    memset(key, 0, sizeof(*key));
    key->type = cfg->type;
    snprintf(key->fqdn, sizeof(key->fqdn), "%s", cfg->fqdn);

    return 0;
}

const char *sepp_target_type_name(enum sepp_target_type type)
{
    switch (type) {
    case SEPP_TARGET_PEER_SEPP:
        return "peer-sepp";
    case SEPP_TARGET_INTERNAL_NF:
        return "internal-nf";
    case SEPP_TARGET_SCP:
        return "scp";
    case SEPP_TARGET_NONE:
    default:
        return "none";
    }
}
