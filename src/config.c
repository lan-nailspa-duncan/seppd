//#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <cjson/cJSON.h>

#include "config.h"

static void parse_string(cJSON *obj,
                         const char *name,
                         char *dst,
                         size_t dst_len);

static void config_copy_string(char *dst, size_t dst_len, const char *src)
{
    if (!dst || dst_len == 0)
        return;

    if (!src)
        src = "";

    snprintf(dst, dst_len, "%s", src);
}

static enum sepp_target_type config_parse_target_type(const char *type)
{
    if (!type)
        return SEPP_TARGET_NONE;

    if (strcmp(type, "peer_sepp") == 0)
        return SEPP_TARGET_PEER_SEPP;

    if (strcmp(type, "scp") == 0)
        return SEPP_TARGET_SCP;

    if (strcmp(type, "nf") == 0 || strcmp(type, "internal_nf") == 0)
        return SEPP_TARGET_INTERNAL_NF;

    return SEPP_TARGET_NONE;
}

static enum sepp_listener_role config_parse_listener_role(const char *role)
{
    if (!role)
        return SEPP_LISTENER_ROLE_NONE;

    if (strcmp(role, "internal_sbi") == 0)
        return SEPP_LISTENER_ROLE_INTERNAL_SBI;

    if (strcmp(role, "external_n32") == 0)
        return SEPP_LISTENER_ROLE_EXTERNAL_N32;

    return SEPP_LISTENER_ROLE_NONE;
}

const char *sepp_listener_role_name(enum sepp_listener_role role)
{
    switch (role) {
    case SEPP_LISTENER_ROLE_INTERNAL_SBI:
        return "internal_sbi";
    case SEPP_LISTENER_ROLE_EXTERNAL_N32:
        return "external_n32";
    case SEPP_LISTENER_ROLE_NONE:
    case SEPP_LISTENER_ROLE_MAX:
    default:
        return "none";
    }
}

const struct sepp_listener_config *sepp_config_listener_by_role(
    const sepp_config_t *cfg,
    enum sepp_listener_role role)
{
    if (!cfg || role <= SEPP_LISTENER_ROLE_NONE ||
        role >= SEPP_LISTENER_ROLE_MAX)
        return NULL;

    for (int i = 0; i < cfg->listener_count; i++) {
        if (cfg->listeners[i].role == role)
            return &cfg->listeners[i];
    }

    return NULL;
}

static void config_set_defaults(sepp_config_t *cfg)
{
    config_copy_string(cfg->log_level, sizeof(cfg->log_level), "DEBUG");

    config_copy_string(cfg->tls.certificate,
                       sizeof(cfg->tls.certificate),
                       "certs/seppd.crt");
    config_copy_string(cfg->tls.private_key,
                       sizeof(cfg->tls.private_key),
                       "certs/seppd.key");
    config_copy_string(cfg->tls.ca_bundle,
                       sizeof(cfg->tls.ca_bundle),
                       "certs/ca.crt");

    cfg->cert_verify.enabled = 0;
    config_copy_string(cfg->cert_verify.local_socket,
                       sizeof(cfg->cert_verify.local_socket),
                       "/tmp/seppd-certverify.sock");
    config_copy_string(cfg->cert_verify.peer_socket,
                       sizeof(cfg->cert_verify.peer_socket),
                       "/tmp/sepp-certverifier.sock");
    cfg->cert_verify.timeout_ms = 3000;

    cfg->ocsp.client_request_server_stapling = 1;
    cfg->ocsp.server_stapling_enabled = 0;
    cfg->internal_route_mode = SEPP_INTERNAL_ROUTE_DIRECT;
    config_copy_string(cfg->ocsp.server_stapling_response_file,
                       sizeof(cfg->ocsp.server_stapling_response_file),
                       "certs/seppd.ocsp.der");
}

static int parse_internal_routing(cJSON *root, sepp_config_t *cfg)
{
    cJSON *routing;
    cJSON *mode;
    cJSON *served_domains;

    routing = cJSON_GetObjectItem(root, "internal_routing");
    if (!cJSON_IsObject(routing))
        return 0;

    mode = cJSON_GetObjectItem(routing, "mode");
    if (!cJSON_IsString(mode))
        return -1;

    served_domains = cJSON_GetObjectItem(routing, "served_domains");
    if (cJSON_IsArray(served_domains)) {
        int count = cJSON_GetArraySize(served_domains);

        if (count > SEPP_CONFIG_MAX_SERVED_DOMAINS)
            return -1;
        for (int i = 0; i < count; i++) {
            cJSON *domain = cJSON_GetArrayItem(served_domains, i);

            if (!cJSON_IsString(domain) || domain->valuestring[0] == '\0')
                return -1;
            config_copy_string(cfg->internal_served_domains[i],
                               sizeof(cfg->internal_served_domains[i]),
                               domain->valuestring);
            cfg->internal_served_domain_count++;
        }
    }

    if (strcmp(mode->valuestring, "direct") == 0) {
        cfg->internal_route_mode = SEPP_INTERNAL_ROUTE_DIRECT;
        cfg->internal_scp[0] = '\0';
        return 0;
    }

    if (strcmp(mode->valuestring, "scp") == 0) {
        cfg->internal_route_mode = SEPP_INTERNAL_ROUTE_SCP;
        parse_string(routing,
                     "scp_target",
                     cfg->internal_scp,
                     sizeof(cfg->internal_scp));
        return cfg->internal_scp[0] == '\0' ? -1 : 0;
    }

    return -1;
}

static void parse_bool(cJSON *obj, const char *name, int *value)
{
    cJSON *item;

    if (!obj || !name || !value)
        return;

    item = cJSON_GetObjectItem(obj, name);
    if (cJSON_IsBool(item))
        *value = cJSON_IsTrue(item) ? 1 : 0;
}

static void parse_string(cJSON *obj, const char *name, char *dst, size_t dst_len)
{
    cJSON *item;

    if (!obj || !name || !dst || dst_len == 0)
        return;

    item = cJSON_GetObjectItem(obj, name);
    if (cJSON_IsString(item))
        config_copy_string(dst, dst_len, item->valuestring);
}

static void parse_u16(cJSON *obj, const char *name, uint16_t *value)
{
    cJSON *item;

    if (!obj || !name || !value)
        return;

    item = cJSON_GetObjectItem(obj, name);
    if (cJSON_IsNumber(item) &&
        item->valueint > 0 &&
        item->valueint <= UINT16_MAX)
        *value = (uint16_t)item->valueint;
}

static void parse_tls_object(cJSON *tls, struct sepp_tls_config *cfg)
{
    if (!cJSON_IsObject(tls) || !cfg)
        return;

    parse_string(tls,
                 "certificate",
                 cfg->certificate,
                 sizeof(cfg->certificate));
    parse_string(tls,
                 "private_key",
                 cfg->private_key,
                 sizeof(cfg->private_key));
    parse_string(tls,
                 "ca_bundle",
                 cfg->ca_bundle,
                 sizeof(cfg->ca_bundle));
    parse_string(tls,
                 "sslkeylogfile",
                 cfg->sslkeylogfile,
                 sizeof(cfg->sslkeylogfile));
}

static void parse_tls(cJSON *root, sepp_config_t *cfg)
{
    cJSON *tls;

    tls = cJSON_GetObjectItem(root, "tls");
    if (!cJSON_IsObject(tls))
        return;

    parse_tls_object(tls, &cfg->tls);
}

static int parse_listeners(cJSON *root, sepp_config_t *cfg)
{
    cJSON *listeners;
    int count;

    listeners = cJSON_GetObjectItem(root, "listeners");
    if (!cJSON_IsArray(listeners)) {
        fprintf(stderr, "listeners array is required\n");
        return -1;
    }

    count = cJSON_GetArraySize(listeners);
    if (count != SEPP_CONFIG_MAX_LISTENERS) {
        fprintf(stderr,
                "exactly %d listeners are required\n",
                SEPP_CONFIG_MAX_LISTENERS);
        return -1;
    }

    cfg->listener_count = count;

    for (int i = 0; i < count; i++) {
        struct sepp_listener_config *listener = &cfg->listeners[i];
        cJSON *item = cJSON_GetArrayItem(listeners, i);
        cJSON *role;
        cJSON *tls;

        if (!cJSON_IsObject(item))
            return -1;

        memcpy(&listener->tls, &cfg->tls, sizeof(listener->tls));
        listener->port = 443;
        listener->require_client_certificate = 1;
        listener->external_certificate_verification = 1;

        role = cJSON_GetObjectItem(item, "role");
        if (cJSON_IsString(role))
            listener->role = config_parse_listener_role(role->valuestring);

        parse_string(item,
                     "address",
                     listener->address,
                     sizeof(listener->address));
        parse_u16(item, "port", &listener->port);
        parse_bool(item,
                   "require_client_certificate",
                   &listener->require_client_certificate);
        parse_bool(item,
                   "external_certificate_verification",
                   &listener->external_certificate_verification);

        tls = cJSON_GetObjectItem(item, "tls");
        if (cJSON_IsObject(tls))
            parse_tls_object(tls, &listener->tls);
    }

    return 0;
}

static int validate_listeners(const sepp_config_t *cfg)
{
    unsigned int roles = 0;

    if (!cfg || cfg->listener_count != SEPP_CONFIG_MAX_LISTENERS)
        return -1;

    for (int i = 0; i < cfg->listener_count; i++) {
        const struct sepp_listener_config *listener = &cfg->listeners[i];
        unsigned int role_bit;

        if (listener->role <= SEPP_LISTENER_ROLE_NONE ||
            listener->role >= SEPP_LISTENER_ROLE_MAX ||
            listener->address[0] == '\0' || listener->port == 0 ||
            listener->tls.certificate[0] == '\0' ||
            listener->tls.private_key[0] == '\0') {
            fprintf(stderr, "invalid listener configuration at index %d\n", i);
            return -1;
        }

        role_bit = 1u << (unsigned int)listener->role;
        if (roles & role_bit) {
            fprintf(stderr,
                    "duplicate listener role %s\n",
                    sepp_listener_role_name(listener->role));
            return -1;
        }
        roles |= role_bit;

        if (listener->require_client_certificate &&
            listener->tls.ca_bundle[0] == '\0') {
            fprintf(stderr,
                    "listener %s requires a client CA bundle\n",
                    sepp_listener_role_name(listener->role));
            return -1;
        }

        if (listener->role == SEPP_LISTENER_ROLE_EXTERNAL_N32 &&
            !listener->require_client_certificate) {
            fprintf(stderr,
                    "external_n32 listener must require a client certificate\n");
            return -1;
        }

        for (int j = 0; j < i; j++) {
            const struct sepp_listener_config *other = &cfg->listeners[j];

            if (listener->port == other->port &&
                strcmp(listener->address, other->address) == 0) {
                fprintf(stderr,
                        "listeners %s and %s use the same endpoint %s:%u\n",
                        sepp_listener_role_name(other->role),
                        sepp_listener_role_name(listener->role),
                        listener->address,
                        (unsigned int)listener->port);
                return -1;
            }
        }
    }

    if (!sepp_config_listener_by_role(
            cfg, SEPP_LISTENER_ROLE_INTERNAL_SBI) ||
        !sepp_config_listener_by_role(
            cfg, SEPP_LISTENER_ROLE_EXTERNAL_N32)) {
        fprintf(stderr,
                "internal_sbi and external_n32 listeners are required\n");
        return -1;
    }

    return 0;
}

static void parse_cert_verify(cJSON *root, sepp_config_t *cfg)
{
    cJSON *cert_verify;
    cJSON *timeout_ms;

    cert_verify = cJSON_GetObjectItem(root, "certificate_verifier");
    if (!cJSON_IsObject(cert_verify))
        cert_verify = cJSON_GetObjectItem(root, "cert_verify");

    if (!cJSON_IsObject(cert_verify))
        return;

    parse_bool(cert_verify, "enabled", &cfg->cert_verify.enabled);
    parse_string(cert_verify,
                 "local_socket",
                 cfg->cert_verify.local_socket,
                 sizeof(cfg->cert_verify.local_socket));
    parse_string(cert_verify,
                 "peer_socket",
                 cfg->cert_verify.peer_socket,
                 sizeof(cfg->cert_verify.peer_socket));

    timeout_ms = cJSON_GetObjectItem(cert_verify, "timeout_ms");
    if (cJSON_IsNumber(timeout_ms) && timeout_ms->valueint > 0)
        cfg->cert_verify.timeout_ms = (uint64_t)timeout_ms->valueint;
}

static void parse_ocsp(cJSON *root, sepp_config_t *cfg)
{
    cJSON *ocsp;
    cJSON *server_stapling;

    ocsp = cJSON_GetObjectItem(root, "ocsp");
    if (!cJSON_IsObject(ocsp))
        return;

    parse_bool(ocsp,
               "client_request_server_stapling",
               &cfg->ocsp.client_request_server_stapling);

    server_stapling = cJSON_GetObjectItem(ocsp, "server_stapling");
    if (!cJSON_IsObject(server_stapling))
        return;

    parse_bool(server_stapling,
               "enabled",
               &cfg->ocsp.server_stapling_enabled);
    parse_string(server_stapling,
                 "response_file",
                 cfg->ocsp.server_stapling_response_file,
                 sizeof(cfg->ocsp.server_stapling_response_file));
}

static int parse_targets(cJSON *root, sepp_config_t *cfg)
{
    cJSON *targets;
    int count;

    targets = cJSON_GetObjectItem(root, "targets");
    if (!cJSON_IsArray(targets))
        return 0;

    count = cJSON_GetArraySize(targets);
    if (count > SEPP_CONFIG_MAX_TARGETS)
        count = SEPP_CONFIG_MAX_TARGETS;

    cfg->target_count = count;

    for (int i = 0; i < count; i++) {
        struct sepp_target_config *target = &cfg->targets[i];
        cJSON *item = cJSON_GetArrayItem(targets, i);
        cJSON *type;
        cJSON *served_domains;

        if (!cJSON_IsObject(item))
            continue;

        target->port = 443;
        target->external_certificate_verification = 1;

        parse_string(item, "name", target->name, sizeof(target->name));
        parse_string(item, "plmn", target->plmn, sizeof(target->plmn));
        parse_string(item, "fqdn", target->fqdn, sizeof(target->fqdn));
        parse_string(item, "nf_type", target->nf_type, sizeof(target->nf_type));
        parse_string(item,
                     "nf_instance_id",
                     target->nf_instance_id,
                     sizeof(target->nf_instance_id));
        parse_u16(item, "port", &target->port);
        parse_u16(item, "n32f_port", &target->n32f_port);
        parse_bool(item,
                   "external_certificate_verification",
                   &target->external_certificate_verification);

        type = cJSON_GetObjectItem(item, "type");
        if (cJSON_IsString(type))
            target->type = config_parse_target_type(type->valuestring);

        served_domains = cJSON_GetObjectItem(item, "served_domains");
        if (cJSON_IsArray(served_domains)) {
            int domain_count = cJSON_GetArraySize(served_domains);

            if (domain_count > SEPP_CONFIG_MAX_SERVED_DOMAINS)
                return -1;
            for (int j = 0; j < domain_count; j++) {
                cJSON *domain = cJSON_GetArrayItem(served_domains, j);

                if (!cJSON_IsString(domain) || domain->valuestring[0] == '\0')
                    return -1;
                config_copy_string(target->served_domains[j],
                                   sizeof(target->served_domains[j]),
                                   domain->valuestring);
                target->served_domain_count++;
            }
        }
    }

    return 0;
}

static int validate_targets(const sepp_config_t *cfg)
{
    if (!cfg)
        return -1;

    for (int i = 0; i < cfg->target_count; i++) {
        const struct sepp_target_config *target = &cfg->targets[i];

        if (target->type == SEPP_TARGET_NONE ||
            target->fqdn[0] == '\0' ||
            target->port == 0) {
            fprintf(stderr, "invalid target configuration at index %d\n", i);
            return -1;
        }

        if (target->type == SEPP_TARGET_PEER_SEPP &&
            target->served_domain_count == 0) {
            fprintf(stderr, "peer target %s requires served_domains\n", target->name);
            return -1;
        }

        if (target->type != SEPP_TARGET_PEER_SEPP &&
            target->served_domain_count != 0) {
            fprintf(stderr, "served_domains is only valid for peer targets\n");
            return -1;
        }

        for (int j = 0; j < i; j++) {
            const struct sepp_target_config *other = &cfg->targets[j];

            if (target->type == other->type &&
                strncmp(target->fqdn,
                        other->fqdn,
                        sizeof(target->fqdn)) == 0) {
                fprintf(stderr,
                        "duplicate logical target type=%s fqdn=%s\n",
                        sepp_target_type_name(target->type),
                        target->fqdn);
                return -1;
            }
        }
    }

    return 0;
}

static int validate_internal_routing(const sepp_config_t *cfg)
{
    if (cfg->internal_route_mode == SEPP_INTERNAL_ROUTE_DIRECT)
        return 0;

    if (cfg->internal_served_domain_count == 0) {
        fprintf(stderr, "SCP internal routing requires served_domains\n");
        return -1;
    }

    for (int i = 0; i < cfg->target_count; i++) {
        if (cfg->targets[i].type == SEPP_TARGET_SCP &&
            strcmp(cfg->targets[i].name, cfg->internal_scp) == 0)
            return 0;
    }

    fprintf(stderr, "internal routing SCP target %s was not found\n",
            cfg->internal_scp);
    return -1;
}

int config_load(const char *path, sepp_config_t *cfg)
{
    FILE *f;
    long len;
    char *data;
    cJSON *root;
    cJSON *plmn;
    cJSON *fqdn;
    cJSON *log;

    if (!path || !cfg)
        return -1;

    memset(cfg, 0, sizeof(*cfg));
    config_set_defaults(cfg);

    f = fopen(path, "r");
    if (!f) {
        perror("config fopen");
        return -1;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }

    len = ftell(f);
    if (len < 0) {
        fclose(f);
        return -1;
    }
    rewind(f);

    data = malloc((size_t)len + 1u);
    if (!data) {
        fclose(f);
        return -1;
    }

    if (fread(data, 1, (size_t)len, f) != (size_t)len) {
        free(data);
        fclose(f);
        return -1;
    }
    data[len] = '\0';
    fclose(f);

    root = cJSON_Parse(data);
    free(data);

    if (!root) {
        fprintf(stderr, "JSON parse error\n");
        return -1;
    }

    plmn = cJSON_GetObjectItem(root, "local_plmn");
    if (cJSON_IsString(plmn))
        config_copy_string(cfg->local_plmn,
                           sizeof(cfg->local_plmn),
                           plmn->valuestring);

    fqdn = cJSON_GetObjectItem(root, "local_fqdn");
    if (cJSON_IsString(fqdn))
        config_copy_string(cfg->local_fqdn,
                           sizeof(cfg->local_fqdn),
                           fqdn->valuestring);

    log = cJSON_GetObjectItem(root, "log_level");
    if (cJSON_IsString(log))
        config_copy_string(cfg->log_level,
                           sizeof(cfg->log_level),
                           log->valuestring);

    parse_tls(root, cfg);
    if (parse_listeners(root, cfg) != 0 || validate_listeners(cfg) != 0) {
        cJSON_Delete(root);
        return -1;
    }
    parse_cert_verify(root, cfg);
    parse_ocsp(root, cfg);
    if (parse_internal_routing(root, cfg) != 0 ||
        parse_targets(root, cfg) != 0 || validate_targets(cfg) != 0 ||
        validate_internal_routing(cfg) != 0) {
        cJSON_Delete(root);
        return -1;
    }

    cJSON_Delete(root);

    return 0;
}

void config_dump(const sepp_config_t *cfg)
{
    printf("local_plmn = %s\n", cfg->local_plmn);
    printf("local_fqdn = %s\n", cfg->local_fqdn);
    printf("log_level  = %s\n", cfg->log_level);
    printf("outbound_tls = certificate=%s private_key=%s ca_bundle=%s\n",
           cfg->tls.certificate,
           cfg->tls.private_key,
           cfg->tls.ca_bundle);

    for (int i = 0; i < cfg->listener_count; i++) {
        const struct sepp_listener_config *listener = &cfg->listeners[i];

        printf("listener[%d]: role=%s endpoint=%s:%u require_client_certificate=%s external_certificate_verification=%s certificate=%s private_key=%s ca_bundle=%s\n",
               i,
               sepp_listener_role_name(listener->role),
               listener->address,
               (unsigned int)listener->port,
               listener->require_client_certificate ? "yes" : "no",
               listener->external_certificate_verification ? "yes" : "no",
               listener->tls.certificate,
               listener->tls.private_key,
               listener->tls.ca_bundle);
    }

    printf("cert_verify = %s local=%s peer=%s timeout_ms=%llu\n",
           cfg->cert_verify.enabled ? "enabled" : "disabled",
           cfg->cert_verify.local_socket,
           cfg->cert_verify.peer_socket,
           (unsigned long long)cfg->cert_verify.timeout_ms);

    printf("ocsp       = client_request_server_stapling=%s server_stapling=%s response_file=%s\n",
           cfg->ocsp.client_request_server_stapling ? "yes" : "no",
           cfg->ocsp.server_stapling_enabled ? "enabled" : "disabled",
           cfg->ocsp.server_stapling_response_file);

    printf("internal_routing = mode=%s scp_target=%s\n",
           cfg->internal_route_mode == SEPP_INTERNAL_ROUTE_SCP ? "scp" : "direct",
           cfg->internal_scp[0] ? cfg->internal_scp : "-");
    for (int i = 0; i < cfg->internal_served_domain_count; i++)
        printf("  internal_served_domain[%d]=%s\n",
               i,
               cfg->internal_served_domains[i]);

    for (int i = 0; i < cfg->target_count; i++) {
        const struct sepp_target_config *target = &cfg->targets[i];

        printf("target[%d]: name=%s type=%s plmn=%s nf_type=%s nf_instance_id=%s fqdn=%s:%u n32f_port=%u external_certificate_verification=%s\n",
               i,
               target->name,
               sepp_target_type_name(target->type),
               target->plmn,
               target->nf_type,
               target->nf_instance_id,
               target->fqdn,
               (unsigned int)target->port,
               (unsigned int)(target->n32f_port ? target->n32f_port : target->port),
               target->external_certificate_verification ? "yes" : "no");
        for (int j = 0; j < target->served_domain_count; j++)
            printf("  served_domain[%d]=%s\n", j, target->served_domains[j]);
    }
}
