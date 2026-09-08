#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>

#include "config.h"
#include "connection.h"
#include "log.h"
#include "object_counter.h"
#include "peer.h"
#include "sepp.h"

static unsigned int peer_target_bucket(const struct sepp_target_key *key)
{
    return sepp_target_hash(key) % SEPP_PEER_BUCKETS;
}

static int peer_config_to_key(const struct sepp_target_config *cfg,
                              struct sepp_target_key *key)
{
    if (!cfg || !key)
        return -1;

    if (cfg->type != SEPP_TARGET_PEER_SEPP)
        return -1;

    return sepp_target_from_config(cfg, key);
}

static struct sepp_peer_ctx *peer_alloc(const struct sepp_target_config *cfg,
                                        const struct sepp_target_key *key)
{
    struct sepp_peer_ctx *peer;

    peer = calloc(1, sizeof(*peer));
    if (!peer)
        return NULL;
    sepp_object_counter_alloc(SEPP_OBJECT_PEER_CONTEXT);

    memcpy(&peer->target, key, sizeof(peer->target));
    peer->port = cfg->port;
    peer->configured_n32f_port = cfg->n32f_port ? cfg->n32f_port : cfg->port;
    snprintf(peer->n32c_peer_fqdn, sizeof(peer->n32c_peer_fqdn), "%s",
             key->fqdn);
    peer->n32c_peer_port = cfg->port;
    snprintf(peer->n32c_peer_path, sizeof(peer->n32c_peer_path),
             "/n32c-handshake/v1/exchange-capability");
    snprintf(peer->n32f_peer_fqdn, sizeof(peer->n32f_peer_fqdn), "%s",
             key->fqdn);
    peer->n32f_peer_port = peer->configured_n32f_port;
    snprintf(peer->plmn, sizeof(peer->plmn), "%s", cfg->plmn);
    peer->n32c_state = SEPP_N32C_STATE_IDLE;
    peer->selected_security = SEPP_SECURITY_CAPABILITY_UNKNOWN;
    sepp_timer_init(&peer->n32c_close_timer);
    sepp_timer_init(&peer->n32c_redirect_timer);
    sepp_list_init(&peer->hash_node);

    return peer;
}

void sepp_peer_table_init(struct sepp_peer_table *table)
{
    if (!table)
        return;

    for (unsigned int i = 0; i < SEPP_PEER_BUCKETS; i++)
        sepp_list_init(&table->buckets[i]);

    table->count = 0;
}

void sepp_peer_table_cleanup(struct sepp_peer_table *table)
{
    if (!table)
        return;

    for (unsigned int i = 0; i < SEPP_PEER_BUCKETS; i++) {
        struct sepp_list *pos;
        struct sepp_list *next;

        sepp_list_for_each_safe(pos, next, &table->buckets[i]) {
            struct sepp_peer_ctx *peer;

            peer = sepp_list_entry(pos, struct sepp_peer_ctx, hash_node);
            sepp_list_del(&peer->hash_node);
            sepp_object_counter_free(SEPP_OBJECT_PEER_CONTEXT);
            free(peer);
        }
    }

    table->count = 0;
}

int sepp_peer_table_load_config(struct sepp_context *ctx,
                                struct sepp_peer_table *table)
{
    if (!ctx || !table)
        return -1;

    for (int i = 0; i < ctx->config.target_count; i++) {
        const struct sepp_target_config *cfg = &ctx->config.targets[i];
        struct sepp_target_key key;
        struct sepp_peer_ctx *peer;
        unsigned int bucket;

        if (cfg->type != SEPP_TARGET_PEER_SEPP)
            continue;

        if (peer_config_to_key(cfg, &key) != 0) {
            SEPP_ERROR("invalid peer_sepp target config at index %d", i);
            return -1;
        }

        if (sepp_peer_lookup_target(table, &key)) {
            SEPP_ERROR("duplicate peer SEPP target %s", key.fqdn);
            return -1;
        }

        peer = peer_alloc(cfg, &key);
        if (!peer)
            return -1;

        bucket = peer_target_bucket(&key);
        sepp_list_add_tail(&peer->hash_node, &table->buckets[bucket]);
        table->count++;

        SEPP_INFO("peer context added fqdn=%s plmn=%s port=%u",
                  peer->target.fqdn,
                  peer->plmn,
                  (unsigned int)peer->port);
    }

    return 0;
}

struct sepp_peer_ctx *sepp_peer_lookup_target(struct sepp_peer_table *table,
                                              const struct sepp_target_key *key)
{
    struct sepp_list *pos;
    unsigned int bucket;

    if (!table || !key)
        return NULL;

    bucket = peer_target_bucket(key);

    sepp_list_for_each(pos, &table->buckets[bucket]) {
        struct sepp_peer_ctx *peer;

        peer = sepp_list_entry(pos, struct sepp_peer_ctx, hash_node);
        if (sepp_target_equal(&peer->target, key))
            return peer;
    }

    return NULL;
}

struct sepp_peer_ctx *sepp_peer_lookup_fqdn(struct sepp_peer_table *table,
                                            const char *fqdn)
{
    struct sepp_target_key key;

    if (!table || !fqdn || fqdn[0] == '\0')
        return NULL;

    memset(&key, 0, sizeof(key));
    key.type = SEPP_TARGET_PEER_SEPP;
    snprintf(key.fqdn, sizeof(key.fqdn), "%s", fqdn);

    return sepp_peer_lookup_target(table, &key);
}

struct sepp_peer_ctx *sepp_peer_lookup_learned_fqdn(
    struct sepp_peer_table *table,
    const char *fqdn)
{
    struct sepp_peer_ctx *match = NULL;

    if (!table || !fqdn || fqdn[0] == '\0')
        return NULL;

    for (unsigned int i = 0; i < SEPP_PEER_BUCKETS; i++) {
        struct sepp_list *pos;

        sepp_list_for_each(pos, &table->buckets[i]) {
            struct sepp_peer_ctx *peer;
            int sender_match;
            int endpoint_match;

            peer = sepp_list_entry(pos, struct sepp_peer_ctx, hash_node);
            sender_match = peer->sender_fqdn[0] != '\0' &&
                           strcasecmp(peer->sender_fqdn, fqdn) == 0;
            endpoint_match = peer->n32c_peer_fqdn[0] != '\0' &&
                             strcasecmp(peer->n32c_peer_fqdn, fqdn) == 0;
            if (!sender_match && !endpoint_match)
                continue;

            if (match && match != peer) {
                SEPP_ERROR("ambiguous learned peer FQDN %s matches %s and %s",
                           fqdn,
                           match->target.fqdn,
                           peer->target.fqdn);
                return NULL;
            }
            match = peer;
        }
    }

    return match;
}

struct sepp_peer_ctx *sepp_peer_lookup_plmn(struct sepp_peer_table *table,
                                            const char *plmn)
{
    if (!table || !plmn || plmn[0] == '\0')
        return NULL;

    for (unsigned int i = 0; i < SEPP_PEER_BUCKETS; i++) {
        struct sepp_list *pos;

        sepp_list_for_each(pos, &table->buckets[i]) {
            struct sepp_peer_ctx *peer;

            peer = sepp_list_entry(pos, struct sepp_peer_ctx, hash_node);
            if (strncmp(peer->plmn, plmn, sizeof(peer->plmn)) == 0)
                return peer;
        }
    }

    return NULL;
}

int sepp_peer_attach_conn(struct sepp_peer_table *table,
                          struct sepp_conn *conn)
{
    struct sepp_peer_ctx *peer;
    struct sepp_conn **slot;

    if (!table || !conn ||
        !(conn->flags & SEPP_CONN_F_HAS_TARGET) ||
        conn->target_key.type != SEPP_TARGET_PEER_SEPP)
        return -1;

    peer = sepp_peer_lookup_target(table, &conn->target_key);
    if (!peer)
        return -1;

    switch (conn->type) {
    case SEPP_CONN_TYPE_N32C:
        slot = &peer->n32c_conn;
        break;
    case SEPP_CONN_TYPE_N32F:
        if (conn->flags & SEPP_CONN_F_STANDBY)
            slot = &peer->n32f_replacement_conn;
        else
            slot = &peer->n32f_conn;
        break;
    default:
        return -1;
    }

    if (*slot && *slot != conn)
        return -1;

    *slot = conn;
    return 0;
}

void sepp_peer_detach_conn(struct sepp_peer_table *table,
                           struct sepp_conn *conn)
{
    struct sepp_peer_ctx *peer;

    if (!table || !conn ||
        !(conn->flags & SEPP_CONN_F_HAS_TARGET) ||
        conn->target_key.type != SEPP_TARGET_PEER_SEPP)
        return;

    peer = sepp_peer_lookup_target(table, &conn->target_key);
    if (!peer)
        return;

    if (peer->n32c_conn == conn) {
        if (conn->ctx && sepp_timer_active(&peer->n32c_close_timer))
            sepp_timer_stop(conn->ctx, &peer->n32c_close_timer);
        peer->n32c_conn = NULL;
        if (peer->n32c_state == SEPP_N32C_STATE_TERMINATING)
            peer->n32c_state = SEPP_N32C_STATE_ESTABLISHED;
        else if (peer->n32c_state != SEPP_N32C_STATE_ESTABLISHED &&
                 peer->n32c_state != SEPP_N32C_STATE_IDLE)
            peer->n32c_state = SEPP_N32C_STATE_FAILED;
    }

    if (peer->n32f_conn == conn)
        peer->n32f_conn = NULL;

    if (peer->n32f_replacement_conn == conn)
        peer->n32f_replacement_conn = NULL;
}

const char *sepp_n32c_state_name(enum sepp_n32c_state state)
{
    switch (state) {
    case SEPP_N32C_STATE_IDLE:
        return "idle";
    case SEPP_N32C_STATE_CONNECTING:
        return "connecting";
    case SEPP_N32C_STATE_EXCHANGE_CAPABILITY:
        return "exchange-capability";
    case SEPP_N32C_STATE_REDIRECTING:
        return "redirecting";
    case SEPP_N32C_STATE_ESTABLISHED:
        return "established";
    case SEPP_N32C_STATE_TERMINATING:
        return "terminating";
    case SEPP_N32C_STATE_FAILED:
    default:
        return "failed";
    }
}

const char *sepp_security_capability_name(
    enum sepp_security_capability capability)
{
    switch (capability) {
    case SEPP_SECURITY_CAPABILITY_TLS:
        return "TLS";
    case SEPP_SECURITY_CAPABILITY_PRINS:
        return "PRINS";
    case SEPP_SECURITY_CAPABILITY_UNKNOWN:
    default:
        return "UNKNOWN";
    }
}
