#ifndef TLS_CHANNEL_H
#define TLS_CHANNEL_H

#include <stddef.h>

#include "config.h"

struct sepp_conn;
struct sepp_context;

struct sepp_tls_mgr {
    void *server_ctx[SEPP_LISTENER_ROLE_MAX];
    void *client_ctx;
    unsigned char *ocsp_response;
    size_t ocsp_response_len;
};

int sepp_tls_mgr_init(struct sepp_context *ctx, struct sepp_tls_mgr *mgr);
void sepp_tls_mgr_cleanup(struct sepp_tls_mgr *mgr);

int sepp_channel_set_tls_server(struct sepp_conn *conn);
int sepp_channel_set_tls_client(struct sepp_conn *conn,
                                const char *expected_fqdn,
                                int external_cert_verify);

/*
 * Return 1 when the TLS peer certificate matches hostname, 0 when it does
 * not match, and -1 when the connection has no usable TLS peer certificate.
 */
int sepp_tls_peer_matches_hostname(const struct sepp_conn *conn,
                                   const char *hostname);

#endif
