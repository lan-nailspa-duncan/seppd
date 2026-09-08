#ifndef PEER_H
#define PEER_H

#include <stdint.h>

#include "list.h"
#include "target.h"
#include "timer.h"

struct sepp_context;
struct sepp_conn;

#define SEPP_PEER_BUCKETS 128u
#define SEPP_PEER_PLMN_LEN 16u

#define SEPP_PEER_F_NFTLST 0x00000001u
#define SEPP_PEER_F_TARGET_API_ROOT 0x00000002u
#define SEPP_N32C_MAX_REDIRECTS 5u

enum sepp_n32c_state {
    SEPP_N32C_STATE_IDLE = 0,
    SEPP_N32C_STATE_CONNECTING,
    SEPP_N32C_STATE_EXCHANGE_CAPABILITY,
    SEPP_N32C_STATE_REDIRECTING,
    SEPP_N32C_STATE_ESTABLISHED,
    SEPP_N32C_STATE_TERMINATING,
    SEPP_N32C_STATE_FAILED,
};

enum sepp_security_capability {
    SEPP_SECURITY_CAPABILITY_UNKNOWN = 0,
    SEPP_SECURITY_CAPABILITY_TLS,
    SEPP_SECURITY_CAPABILITY_PRINS,
};

struct sepp_peer_ctx {
    struct sepp_target_key target;
    uint16_t port;
    uint16_t configured_n32f_port; /* from target config; falls back to port */
    char plmn[SEPP_PEER_PLMN_LEN];

    /* Peer identities received during N32-C capability negotiation. */
    char sender_fqdn[SEPP_TARGET_FQDN_MAX];
    char sender_n32f_fqdn[SEPP_TARGET_FQDN_MAX];
    /* The configured target remains the table key.  These are the final
     * endpoints selected by N32-C redirection and capability negotiation. */
    char n32c_peer_fqdn[SEPP_TARGET_FQDN_MAX];
    uint16_t n32c_peer_port;
    char n32c_peer_path[SEPP_TARGET_FQDN_MAX];
    char n32f_peer_fqdn[SEPP_TARGET_FQDN_MAX];
    uint16_t n32f_peer_port;
    unsigned int n32c_redirect_count;
    enum sepp_n32c_state n32c_state;
    enum sepp_security_capability selected_security;
    uint32_t negotiated_features;

    struct sepp_conn *n32c_conn;
    struct sepp_conn *n32f_conn;
    struct sepp_conn *n32f_replacement_conn;
    struct sepp_timer n32c_close_timer;
    struct sepp_timer n32c_redirect_timer;

    struct sepp_list hash_node;
};

struct sepp_peer_table {
    struct sepp_list buckets[SEPP_PEER_BUCKETS];
    unsigned int count;
};

void sepp_peer_table_init(struct sepp_peer_table *table);
void sepp_peer_table_cleanup(struct sepp_peer_table *table);

int sepp_peer_table_load_config(struct sepp_context *ctx,
                                struct sepp_peer_table *table);

struct sepp_peer_ctx *sepp_peer_lookup_target(struct sepp_peer_table *table,
                                              const struct sepp_target_key *key);
struct sepp_peer_ctx *sepp_peer_lookup_fqdn(struct sepp_peer_table *table,
                                            const char *fqdn);
struct sepp_peer_ctx *sepp_peer_lookup_learned_fqdn(
    struct sepp_peer_table *table,
    const char *fqdn);
struct sepp_peer_ctx *sepp_peer_lookup_plmn(struct sepp_peer_table *table,
                                            const char *plmn);

int sepp_peer_attach_conn(struct sepp_peer_table *table,
                          struct sepp_conn *conn);
void sepp_peer_detach_conn(struct sepp_peer_table *table,
                           struct sepp_conn *conn);

const char *sepp_n32c_state_name(enum sepp_n32c_state state);
const char *sepp_security_capability_name(
    enum sepp_security_capability capability);

#endif /* PEER_H */
