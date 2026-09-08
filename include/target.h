#ifndef TARGET_H
#define TARGET_H

struct sepp_target_config;

#define SEPP_TARGET_FQDN_MAX 128

enum sepp_target_type {
    SEPP_TARGET_NONE = 0,
    SEPP_TARGET_PEER_SEPP,
    SEPP_TARGET_INTERNAL_NF,
    SEPP_TARGET_SCP,
};

struct sepp_target_key {
    enum sepp_target_type type;
    char fqdn[SEPP_TARGET_FQDN_MAX];
};

unsigned int sepp_target_hash(const struct sepp_target_key *key);
int sepp_target_equal(const struct sepp_target_key *a,
                      const struct sepp_target_key *b);
int sepp_target_from_config(const struct sepp_target_config *cfg,
                            struct sepp_target_key *key);
const char *sepp_target_type_name(enum sepp_target_type type);

#endif /* TARGET_H */
