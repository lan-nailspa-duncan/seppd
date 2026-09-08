#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

#include "target.h"

#define SEPP_CONFIG_MAX_TARGETS 32
#define SEPP_CONFIG_NAME_LEN    64
#define SEPP_CONFIG_PLMN_LEN    16
#define SEPP_CONFIG_FQDN_LEN    128
#define SEPP_CONFIG_NF_TYPE_LEN 16
#define SEPP_CONFIG_NF_ID_LEN   128
#define SEPP_CONFIG_PATH_LEN    256
#define SEPP_CONFIG_SOCK_LEN    108
#define SEPP_CONFIG_ADDR_LEN    64
#define SEPP_CONFIG_LOG_LEN     16
#define SEPP_CONFIG_MAX_LISTENERS 2
#define SEPP_CONFIG_MAX_SERVED_DOMAINS 8

enum sepp_internal_route_mode {
    SEPP_INTERNAL_ROUTE_DIRECT = 0,
    SEPP_INTERNAL_ROUTE_SCP,
};

enum sepp_listener_role {
    SEPP_LISTENER_ROLE_NONE = 0,
    SEPP_LISTENER_ROLE_INTERNAL_SBI,
    SEPP_LISTENER_ROLE_EXTERNAL_N32,
    SEPP_LISTENER_ROLE_MAX,
};

struct sepp_tls_config {
    char certificate[SEPP_CONFIG_PATH_LEN];
    char private_key[SEPP_CONFIG_PATH_LEN];
    char ca_bundle[SEPP_CONFIG_PATH_LEN];
    char sslkeylogfile[SEPP_CONFIG_PATH_LEN]; /* optional NSS keylog output */
};

struct sepp_listener_config {
    enum sepp_listener_role role;
    char address[SEPP_CONFIG_ADDR_LEN];
    uint16_t port;
    int require_client_certificate;
    int external_certificate_verification;
    struct sepp_tls_config tls;
};

struct sepp_cert_verify_config {
    int enabled;
    char local_socket[SEPP_CONFIG_SOCK_LEN];
    char peer_socket[SEPP_CONFIG_SOCK_LEN];
    uint64_t timeout_ms;
};

struct sepp_ocsp_config {
    int client_request_server_stapling;
    int server_stapling_enabled;
    char server_stapling_response_file[SEPP_CONFIG_PATH_LEN];
};

struct sepp_target_config {
    char name[SEPP_CONFIG_NAME_LEN];
    enum sepp_target_type type;
    char plmn[SEPP_CONFIG_PLMN_LEN];
    char fqdn[SEPP_CONFIG_FQDN_LEN];
    uint16_t port;
    uint16_t n32f_port; /* peer_sepp only; 0 means "same as port" */
    char nf_type[SEPP_CONFIG_NF_TYPE_LEN];
    char nf_instance_id[SEPP_CONFIG_NF_ID_LEN];
    int external_certificate_verification;
    char served_domains[SEPP_CONFIG_MAX_SERVED_DOMAINS][SEPP_CONFIG_FQDN_LEN];
    int served_domain_count;
};

typedef struct sepp_config {
    char local_plmn[SEPP_CONFIG_PLMN_LEN];
    char local_fqdn[SEPP_CONFIG_FQDN_LEN];
    char log_level[SEPP_CONFIG_LOG_LEN];

    struct sepp_listener_config listeners[SEPP_CONFIG_MAX_LISTENERS];
    int listener_count;

    /* TLS identity and trust used by outbound connections. */
    struct sepp_tls_config tls;
    struct sepp_cert_verify_config cert_verify;
    struct sepp_ocsp_config ocsp;

    enum sepp_internal_route_mode internal_route_mode;
    char internal_scp[SEPP_CONFIG_NAME_LEN];
    char internal_served_domains[SEPP_CONFIG_MAX_SERVED_DOMAINS][SEPP_CONFIG_FQDN_LEN];
    int internal_served_domain_count;

    struct sepp_target_config targets[SEPP_CONFIG_MAX_TARGETS];
    int target_count;
} sepp_config_t;

int config_load(const char *path, sepp_config_t *cfg);

void config_dump(const sepp_config_t *cfg);

const char *sepp_listener_role_name(enum sepp_listener_role role);
const struct sepp_listener_config *sepp_config_listener_by_role(
    const sepp_config_t *cfg,
    enum sepp_listener_role role);


#endif
