#ifndef CERT_VERIFY_H
#define CERT_VERIFY_H

#include <stddef.h>
#include <stdint.h>

#include "ipc.h"
#include "list.h"

struct sepp_context;
struct sepp_cert_verify_req;

#define SEPP_CERT_VERIFY_MAX_CERTS 8u

#define SEPP_CERT_VERIFY_RESULT_ALLOW 1u
#define SEPP_CERT_VERIFY_RESULT_DENY  2u
#define SEPP_CERT_VERIFY_RESULT_ERROR 3u

enum sepp_cert_verify_role {
    SEPP_CERT_VERIFY_ROLE_CLIENT = 1,
    SEPP_CERT_VERIFY_ROLE_SERVER = 2,
};

struct sepp_cert_der {
    const unsigned char *data;
    size_t len;
};

struct sepp_cert_verify_req_payload {
    uint16_t role;
    uint16_t cert_count;
    uint32_t flags;
    uint32_t expected_fqdn_len;
    uint32_t ocsp_response_len;
};

struct sepp_cert_verify_rsp_payload {
    uint32_t result;
    uint32_t reason;
};

typedef void (*sepp_cert_verify_cb)(struct sepp_cert_verify_req *req,
                                    uint32_t result,
                                    uint32_t reason,
                                    void *arg);

struct sepp_cert_verify_req {
    struct sepp_ipc_req ipc_req;
    sepp_cert_verify_cb cb;
    void *arg;
};

struct sepp_cert_verify_client {
    struct sepp_context *ctx;
    struct sepp_ipc_client ipc;
    int enabled;
    uint64_t timeout_ms;
};

void sepp_cert_verify_req_init(struct sepp_cert_verify_req *req);

int sepp_cert_verify_client_init(struct sepp_context *ctx,
                                 struct sepp_cert_verify_client *client);

void sepp_cert_verify_client_cleanup(struct sepp_cert_verify_client *client);

int sepp_cert_verify_request(struct sepp_cert_verify_client *client,
                             struct sepp_cert_verify_req *req,
                             enum sepp_cert_verify_role role,
                             const char *expected_fqdn,
                             const struct sepp_cert_der *certs,
                             unsigned int cert_count,
                             const unsigned char *ocsp_response,
                             size_t ocsp_response_len,
                             sepp_cert_verify_cb cb,
                             void *arg);

void sepp_cert_verify_cancel(struct sepp_cert_verify_client *client,
                             struct sepp_cert_verify_req *req);

#endif
