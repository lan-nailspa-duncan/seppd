#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cert_verify.h"
#include "config.h"
#include "ipc.h"
#include "log.h"
#include "sepp.h"

struct cert_verify_cert_len {
    uint32_t len;
};

static void cert_verify_complete(struct sepp_cert_verify_req *req,
                                 uint32_t result,
                                 uint32_t reason)
{
    sepp_cert_verify_cb cb;
    void *arg;

    if (!req)
        return;

    cb = req->cb;
    arg = req->arg;
    req->cb = NULL;
    req->arg = NULL;

    if (cb)
        cb(req, result, reason, arg);
}

static void cert_verify_ipc_response(struct sepp_ipc_client *ipc,
                                     struct sepp_ipc_req *ipc_req,
                                     const void *payload,
                                     size_t payload_len,
                                     void *arg)
{
    struct sepp_cert_verify_req *req;
    const struct sepp_cert_verify_rsp_payload *rsp;

    (void)ipc;
    (void)arg;

    if (!ipc_req)
        return;

    req = sepp_container_of(ipc_req, struct sepp_cert_verify_req, ipc_req);

    if (!payload || payload_len < sizeof(*rsp)) {
        cert_verify_complete(req,
                             SEPP_CERT_VERIFY_RESULT_ERROR,
                             EINVAL);
        sepp_cert_verify_req_init(req);
        return;
    }

    rsp = payload;
    cert_verify_complete(req, rsp->result, rsp->reason);
    sepp_cert_verify_req_init(req);
}

static void cert_verify_ipc_timeout(struct sepp_ipc_client *ipc,
                                    struct sepp_ipc_req *ipc_req,
                                    void *arg)
{
    struct sepp_cert_verify_req *req;

    (void)ipc;
    (void)arg;

    if (!ipc_req)
        return;

    req = sepp_container_of(ipc_req, struct sepp_cert_verify_req, ipc_req);
    cert_verify_complete(req, SEPP_CERT_VERIFY_RESULT_ERROR, ETIMEDOUT);
    sepp_cert_verify_req_init(req);
}

static int cert_verify_build_payload(unsigned char *buf,
                                     size_t buf_len,
                                     size_t *payload_len,
                                     enum sepp_cert_verify_role role,
                                     const char *expected_fqdn,
                                     const struct sepp_cert_der *certs,
                                     unsigned int cert_count,
                                     const unsigned char *ocsp_response,
                                     size_t ocsp_response_len)
{
    struct sepp_cert_verify_req_payload hdr;
    size_t off;
    size_t fqdn_len;

    if (!buf || !payload_len || !certs || cert_count == 0 ||
        cert_count > SEPP_CERT_VERIFY_MAX_CERTS)
        return -1;

    fqdn_len = expected_fqdn ? strlen(expected_fqdn) : 0u;
    if (fqdn_len > UINT32_MAX || ocsp_response_len > UINT32_MAX)
        return -1;

    if (ocsp_response_len > 0 && !ocsp_response)
        return -1;

    memset(&hdr, 0, sizeof(hdr));
    hdr.role = (uint16_t)role;
    hdr.cert_count = (uint16_t)cert_count;
    hdr.flags = 0;
    hdr.expected_fqdn_len = (uint32_t)fqdn_len;
    hdr.ocsp_response_len = (uint32_t)ocsp_response_len;

    off = 0;
    if (buf_len < sizeof(hdr))
        return -1;

    memcpy(buf + off, &hdr, sizeof(hdr));
    off += sizeof(hdr);

    if (fqdn_len > 0) {
        if (buf_len - off < fqdn_len)
            return -1;
        memcpy(buf + off, expected_fqdn, fqdn_len);
        off += fqdn_len;
    }

    if (ocsp_response_len > 0) {
        if (buf_len - off < ocsp_response_len)
            return -1;
        memcpy(buf + off, ocsp_response, ocsp_response_len);
        off += ocsp_response_len;
    }

    for (unsigned int i = 0; i < cert_count; i++) {
        struct cert_verify_cert_len cert_len;

        if (!certs[i].data || certs[i].len == 0 || certs[i].len > UINT32_MAX)
            return -1;

        cert_len.len = (uint32_t)certs[i].len;

        if (buf_len - off < sizeof(cert_len))
            return -1;
        memcpy(buf + off, &cert_len, sizeof(cert_len));
        off += sizeof(cert_len);

        if (buf_len - off < certs[i].len)
            return -1;
        memcpy(buf + off, certs[i].data, certs[i].len);
        off += certs[i].len;
    }

    *payload_len = off;
    return 0;
}

void sepp_cert_verify_req_init(struct sepp_cert_verify_req *req)
{
    if (!req)
        return;

    sepp_ipc_req_init(&req->ipc_req);
    req->cb = NULL;
    req->arg = NULL;
}

int sepp_cert_verify_client_init(struct sepp_context *ctx,
                                 struct sepp_cert_verify_client *client)
{
    const struct sepp_cert_verify_config *cfg;

    if (!ctx || !client)
        return -1;

    memset(client, 0, sizeof(*client));
    client->ctx = ctx;
    client->timeout_ms = 0;

    cfg = &ctx->config.cert_verify;
    client->enabled = cfg->enabled;
    client->timeout_ms = cfg->timeout_ms;

    if (!client->enabled) {
        SEPP_INFO("external certificate verifier disabled");
        return 0;
    }

    if (sepp_ipc_client_init(ctx,
                             &client->ipc,
                             cfg->local_socket,
                             cfg->peer_socket) != 0) {
        SEPP_ERROR("certificate verifier ipc init failed");
        memset(client, 0, sizeof(*client));
        return -1;
    }

    SEPP_INFO("external certificate verifier enabled");
    return 0;
}

void sepp_cert_verify_client_cleanup(struct sepp_cert_verify_client *client)
{
    if (!client)
        return;

    if (client->enabled)
        sepp_ipc_client_cleanup(&client->ipc);

    memset(client, 0, sizeof(*client));
}

int sepp_cert_verify_request(struct sepp_cert_verify_client *client,
                             struct sepp_cert_verify_req *req,
                             enum sepp_cert_verify_role role,
                             const char *expected_fqdn,
                             const struct sepp_cert_der *certs,
                             unsigned int cert_count,
                             const unsigned char *ocsp_response,
                             size_t ocsp_response_len,
                             sepp_cert_verify_cb cb,
                             void *arg)
{
    unsigned char payload[SEPP_IPC_MAX_PAYLOAD];
    size_t payload_len;

    if (!client || !req || !cb)
        return -1;

    if (!client->enabled)
        return -1;

    if (role != SEPP_CERT_VERIFY_ROLE_CLIENT &&
        role != SEPP_CERT_VERIFY_ROLE_SERVER)
        return -1;

    if (cert_verify_build_payload(payload,
                                  sizeof(payload),
                                  &payload_len,
                                  role,
                                  expected_fqdn,
                                  certs,
                                  cert_count,
                                  ocsp_response,
                                  ocsp_response_len) != 0)
        return -1;

    sepp_cert_verify_req_init(req);
    req->cb = cb;
    req->arg = arg;

    if (sepp_ipc_send_request_type(&client->ipc,
                                   &req->ipc_req,
                                   SEPP_IPC_MSG_CERT_VERIFY_REQ,
                                   SEPP_IPC_MSG_CERT_VERIFY_RSP,
                                   payload,
                                   payload_len,
                                   client->timeout_ms,
                                   cert_verify_ipc_response,
                                   cert_verify_ipc_timeout,
                                   NULL) != 0) {
        sepp_cert_verify_req_init(req);
        return -1;
    }

    return 0;
}

void sepp_cert_verify_cancel(struct sepp_cert_verify_client *client,
                             struct sepp_cert_verify_req *req)
{
    if (!client || !req)
        return;

    if (client->enabled)
        sepp_ipc_cancel_request(&client->ipc, &req->ipc_req);

    sepp_cert_verify_req_init(req);
}
