#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "cert_verify.h"
#include "channel.h"
#include "connection.h"
#include "event.h"
#include "http2.h"
#include "log.h"
#include "n32c.h"
#include "object_counter.h"
#include "sepp.h"
#include "sepp_msg.h"
#include "tls_channel.h"

#define SEPP_TLS_READ_BUF_SIZE 4096
#define SEPP_TLS_EXPECTED_FQDN_LEN 128

struct sepp_tls_conn {
    SSL *ssl;
    int is_server;
    int handshake_done;
    int waiting_cert_verify;
    int external_cert_verify;
    char expected_fqdn[SEPP_TLS_EXPECTED_FQDN_LEN];
    struct sepp_cert_verify_req verify_req;
};

static int tls_verify_allow_cb(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    (void)preverify_ok;
    (void)x509_ctx;
    return 1;
}

static unsigned long tls_last_error(void)
{
    unsigned long err = ERR_peek_last_error();

    if (err == 0)
        err = ERR_get_error();

    return err;
}

static int tls_set_events(struct sepp_conn *conn, uint32_t events)
{
    if (!conn || conn->ev.fd < 0)
        return -1;

    return event_mod(&conn->ctx->events, &conn->ev, events | EPOLLRDHUP);
}

static int tls_finish_tcp_connect(struct sepp_conn *conn)
{
    int error = 0;
    socklen_t error_len = sizeof(error);

    if (getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &error, &error_len) != 0) {
        SEPP_ERROR("getsockopt(SO_ERROR) on fd %d failed: %s",
                   conn->fd,
                   strerror(errno));
        return -1;
    }

    if (error != 0) {
        SEPP_ERROR("outbound TLS TCP connect fd %d failed: %s",
                   conn->fd,
                   strerror(error));
        return -1;
    }

    conn->flags &= ~SEPP_CONN_F_CONNECTING;
    SEPP_INFO("outbound TCP connection fd %d established; starting TLS", conn->fd);

    return 0;
}

static void tls_free_der_certs(struct sepp_cert_der *certs,
                               unsigned int cert_count)
{
    for (unsigned int i = 0; i < cert_count; i++) {
        free((void *)certs[i].data);
        certs[i].data = NULL;
        certs[i].len = 0;
    }
}

static int tls_cert_to_der(X509 *cert, struct sepp_cert_der *der)
{
    unsigned char *buf = NULL;
    unsigned char *p;
    int len;

    if (!cert || !der)
        return -1;

    len = i2d_X509(cert, NULL);
    if (len <= 0)
        return -1;

    buf = malloc((size_t)len);
    if (!buf)
        return -1;

    p = buf;
    if (i2d_X509(cert, &p) != len) {
        free(buf);
        return -1;
    }

    der->data = buf;
    der->len = (size_t)len;

    return 0;
}

static int tls_collect_peer_chain(struct sepp_tls_conn *tls,
                                  struct sepp_cert_der *certs,
                                  unsigned int *cert_count)
{
    STACK_OF(X509) *chain;
    X509 *leaf;
    unsigned int count = 0;

    if (!tls || !certs || !cert_count)
        return -1;

    memset(certs, 0, sizeof(*certs) * SEPP_CERT_VERIFY_MAX_CERTS);
    *cert_count = 0;

    leaf = SSL_get1_peer_certificate(tls->ssl);
    if (!leaf)
        return -1;

    if (tls_cert_to_der(leaf, &certs[count]) != 0) {
        X509_free(leaf);
        return -1;
    }
    count++;

    chain = SSL_get_peer_cert_chain(tls->ssl);
    if (chain) {
        int n = sk_X509_num(chain);

        for (int i = 0; i < n && count < SEPP_CERT_VERIFY_MAX_CERTS; i++) {
            X509 *cert = sk_X509_value(chain, i);

            if (cert == leaf)
                continue;

            if (tls_cert_to_der(cert, &certs[count]) != 0) {
                X509_free(leaf);
                tls_free_der_certs(certs, count);
                return -1;
            }
            count++;
        }
    }

    X509_free(leaf);
    *cert_count = count;

    return 0;
}

static void tls_mark_established(struct sepp_conn *conn)
{
    struct sepp_tls_conn *tls = conn->channel.priv;

    tls->waiting_cert_verify = 0;
    conn->flags |= SEPP_CONN_F_ESTABLISHED;

    SEPP_INFO("TLS channel established on fd %d", conn->fd);

    if (sepp_http2_start(conn, tls->is_server) != 0) {
        SEPP_ERROR("failed to start HTTP/2 session on fd %d", conn->fd);
        sepp_conn_destroy(conn->ctx, conn);
        return;
    }

    if (sepp_msg_attach_http2(conn->ctx, conn) != 0) {
        SEPP_ERROR("failed to attach SEPP message dispatcher on fd %d", conn->fd);
        sepp_conn_destroy(conn->ctx, conn);
        return;
    }

    if (!tls->is_server && conn->type == SEPP_CONN_TYPE_N32F &&
        (conn->flags & SEPP_CONN_F_STANDBY) &&
        sepp_target_n32f_conn_ready(conn->ctx, conn) != 0) {
        SEPP_ERROR("failed to promote standby N32-F connection fd %d",
                   conn->fd);
        sepp_conn_destroy(conn->ctx, conn);
        return;
    }

    if (!tls->is_server && conn->type == SEPP_CONN_TYPE_N32C &&
        sepp_n32c_on_conn_ready(conn->ctx, conn) != 0) {
        SEPP_ERROR("failed to start N32-C capability exchange on fd %d",
                   conn->fd);
        sepp_conn_destroy(conn->ctx, conn);
    }
}

static void tls_cert_verify_done(struct sepp_cert_verify_req *req,
                                 uint32_t result,
                                 uint32_t reason,
                                 void *arg)
{
    struct sepp_conn *conn = arg;
    struct sepp_tls_conn *tls;

    (void)req;

    if (!conn || !conn->channel.priv)
        return;

    tls = conn->channel.priv;
    tls->waiting_cert_verify = 0;

    if (result == SEPP_CERT_VERIFY_RESULT_ALLOW) {
        tls_mark_established(conn);
        return;
    }

    SEPP_ERROR("external certificate verification denied fd %d result %u reason %u",
               conn->fd,
               result,
               reason);
    sepp_conn_destroy(conn->ctx, conn);
}

static int tls_start_external_verify(struct sepp_conn *conn)
{
    struct sepp_tls_conn *tls = conn->channel.priv;
    struct sepp_cert_der certs[SEPP_CERT_VERIFY_MAX_CERTS];
    unsigned int cert_count = 0;
    enum sepp_cert_verify_role role;
    const char *expected_fqdn = NULL;
    const unsigned char *ocsp_response = NULL;
    int ocsp_response_len = -1;
    int rc;

    if (!tls)
        return -1;

    if (!tls->external_cert_verify || !conn->ctx->cert_verify.enabled) {
        tls_mark_established(conn);
        return 0;
    }

    if (tls_collect_peer_chain(tls, certs, &cert_count) != 0) {
        SEPP_ERROR("failed to collect peer certificate chain on fd %d", conn->fd);
        return -1;
    }

    role = tls->is_server ?
           SEPP_CERT_VERIFY_ROLE_SERVER : SEPP_CERT_VERIFY_ROLE_CLIENT;
    if (!tls->is_server) {
        expected_fqdn = tls->expected_fqdn;
        ocsp_response_len = SSL_get_tlsext_status_ocsp_resp(tls->ssl,
                                                            &ocsp_response);
        if (ocsp_response_len < 0) {
            ocsp_response = NULL;
            ocsp_response_len = 0;
        }
    } else {
        ocsp_response_len = 0;
    }

    tls->waiting_cert_verify = 1;
    rc = sepp_cert_verify_request(&conn->ctx->cert_verify,
                                  &tls->verify_req,
                                  role,
                                  expected_fqdn,
                                  certs,
                                  cert_count,
                                  ocsp_response,
                                  (size_t)ocsp_response_len,
                                  tls_cert_verify_done,
                                  conn);
    tls_free_der_certs(certs, cert_count);

    if (rc != 0) {
        tls->waiting_cert_verify = 0;
        SEPP_ERROR("failed to send external certificate verification request for fd %d",
                   conn->fd);
        return -1;
    }

    SEPP_INFO("TLS fd %d waiting for external certificate verification", conn->fd);
    return 0;
}

static int tls_handle_ssl_result(struct sepp_conn *conn, int rc)
{
    struct sepp_tls_conn *tls = conn->channel.priv;
    int err;

    if (rc > 0)
        return 1;

    err = SSL_get_error(tls->ssl, rc);
    if (err == SSL_ERROR_WANT_READ) {
        if (tls_set_events(conn, EPOLLIN) != 0)
            return -1;
        return 0;
    }

    if (err == SSL_ERROR_WANT_WRITE) {
        if (tls_set_events(conn, EPOLLIN | EPOLLOUT) != 0)
            return -1;
        return 0;
    }

    if (err == SSL_ERROR_ZERO_RETURN)
        return -1;

    SEPP_ERROR("TLS operation on fd %d failed: ssl_error=%d openssl_error=%lu",
               conn->fd,
               err,
               tls_last_error());
    return -1;
}

static int tls_drive_handshake(struct sepp_conn *conn)
{
    struct sepp_tls_conn *tls = conn->channel.priv;
    int rc;
    int status;

    if (!tls)
        return -1;

    if (tls->handshake_done || tls->waiting_cert_verify)
        return 0;

    rc = SSL_do_handshake(tls->ssl);
    status = tls_handle_ssl_result(conn, rc);
    if (status <= 0)
        return status;

    tls->handshake_done = 1;
    {
        const char *version = SSL_get_version(tls->ssl);
        const SSL_CIPHER *cipher = SSL_get_current_cipher(tls->ssl);
        const char *cipher_name = cipher ? SSL_CIPHER_get_name(cipher) : "?";
        const unsigned char *alpn = NULL;
        unsigned int alpn_len = 0;
        X509 *peer_cert = SSL_get1_peer_certificate(tls->ssl);
        char peer_subject[256] = "none";

        SSL_get0_alpn_selected(tls->ssl, &alpn, &alpn_len);
        if (peer_cert) {
            X509_NAME_oneline(X509_get_subject_name(peer_cert),
                              peer_subject, sizeof(peer_subject));
            X509_free(peer_cert);
        }

        SEPP_DEBUG("TLS handshake complete on fd %d: version=%s cipher=%s "
                   "alpn=%.*s peer_subject=%s",
                   conn->fd,
                   version ? version : "?",
                   cipher_name,
                   (int)alpn_len,
                   alpn ? (const char *)alpn : "",
                   peer_subject);
    }

    return tls_start_external_verify(conn);
}

static ssize_t tls_read(struct sepp_conn *conn, void *buf, size_t len)
{
    struct sepp_tls_conn *tls;
    int rc;
    int status;

    if (!conn || !conn->channel.priv) {
        errno = ENOTCONN;
        return -1;
    }

    if (!(conn->flags & SEPP_CONN_F_ESTABLISHED)) {
        errno = EAGAIN;
        return -1;
    }

    tls = conn->channel.priv;
    rc = SSL_read(tls->ssl, buf, (int)len);
    if (rc > 0)
        return rc;

    status = tls_handle_ssl_result(conn, rc);
    if (status == 0) {
        errno = EAGAIN;
        return -1;
    }

    errno = EIO;
    return -1;
}

static ssize_t tls_write(struct sepp_conn *conn, const void *buf, size_t len)
{
    struct sepp_tls_conn *tls;
    int rc;
    int status;

    if (!conn || !conn->channel.priv) {
        errno = ENOTCONN;
        return -1;
    }

    if (!(conn->flags & SEPP_CONN_F_ESTABLISHED)) {
        errno = EAGAIN;
        return -1;
    }

    tls = conn->channel.priv;
    rc = SSL_write(tls->ssl, buf, (int)len);
    if (rc > 0)
        return rc;

    status = tls_handle_ssl_result(conn, rc);
    if (status == 0) {
        errno = EAGAIN;
        return -1;
    }

    errno = EIO;
    return -1;
}

static int tls_read_available(struct sepp_conn *conn)
{
    char buf[SEPP_TLS_READ_BUF_SIZE];

    if (conn->http2)
        return sepp_http2_on_readable(conn);

    for (;;) {
        ssize_t nread = tls_read(conn, buf, sizeof(buf));

        if (nread > 0) {
            SEPP_DEBUG("TLS received %zd bytes on fd %d", nread, conn->fd);
            continue;
        }

        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;

        return -1;
    }
}

static int tls_on_event(struct sepp_conn *conn, uint32_t event_flags)
{
    struct sepp_tls_conn *tls;

    if (!conn || !conn->channel.priv)
        return -1;

    tls = conn->channel.priv;

    if ((conn->flags & SEPP_CONN_F_CONNECTING) &&
        (event_flags & EPOLLOUT)) {
        if (tls_finish_tcp_connect(conn) != 0)
            return -1;
        event_flags &= ~EPOLLOUT;
    }

    if (event_flags & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
        SEPP_INFO("TLS fd %d closed by event 0x%x", conn->fd, event_flags);
        return -1;
    }

    if (!tls->handshake_done) {
        if (tls_drive_handshake(conn) != 0)
            return -1;
        return 0;
    }

    if (tls->waiting_cert_verify)
        return 0;

    if ((event_flags & EPOLLOUT) && conn->http2) {
        if (sepp_http2_on_writable(conn) != 0)
            return -1;
    }

    if (event_flags & EPOLLIN)
        return tls_read_available(conn);

    return 0;
}

static void tls_close(struct sepp_conn *conn)
{
    struct sepp_tls_conn *tls;

    if (!conn || !conn->channel.priv)
        return;

    tls = conn->channel.priv;

    if (tls->waiting_cert_verify)
        sepp_cert_verify_cancel(&conn->ctx->cert_verify, &tls->verify_req);

    if (tls->ssl) {
        SSL_shutdown(tls->ssl);
        SSL_free(tls->ssl);
        tls->ssl = NULL;
    }

    sepp_object_counter_free(SEPP_OBJECT_TLS_CHANNEL);
    free(tls);
    conn->channel.priv = NULL;
}

static const struct sepp_channel_ops tls_ops = {
    .type = SEPP_CHANNEL_TLS,
    .name = "tls",
    .read = tls_read,
    .write = tls_write,
    .on_event = tls_on_event,
    .close = tls_close,
};

static int tls_status_cb(SSL *ssl, void *arg)
{
    struct sepp_tls_mgr *mgr = arg;
    unsigned char *resp;

    (void)ssl;

    if (!mgr || !mgr->ocsp_response || mgr->ocsp_response_len == 0)
        return SSL_TLSEXT_ERR_NOACK;

    resp = OPENSSL_memdup(mgr->ocsp_response, mgr->ocsp_response_len);
    if (!resp)
        return SSL_TLSEXT_ERR_NOACK;

    SSL_set_tlsext_status_ocsp_resp(ssl, resp, (int)mgr->ocsp_response_len);
    return SSL_TLSEXT_ERR_OK;
}

static int tls_load_ocsp_response(struct sepp_context *ctx,
                                  struct sepp_tls_mgr *mgr)
{
    FILE *fp;
    long size;
    unsigned char *buf;
    const char *path;

    if (!ctx->config.ocsp.server_stapling_enabled)
        return 0;

    path = ctx->config.ocsp.server_stapling_response_file;
    if (path[0] == '\0')
        return -1;

    fp = fopen(path, "rb");
    if (!fp) {
        SEPP_ERROR("failed to open OCSP response file %s: %s",
                   path,
                   strerror(errno));
        return -1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }

    size = ftell(fp);
    if (size <= 0) {
        fclose(fp);
        return -1;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    buf = malloc((size_t)size);
    if (!buf) {
        fclose(fp);
        return -1;
    }

    if (fread(buf, 1, (size_t)size, fp) != (size_t)size) {
        free(buf);
        fclose(fp);
        return -1;
    }

    fclose(fp);
    mgr->ocsp_response = buf;
    mgr->ocsp_response_len = (size_t)size;

    SEPP_INFO("loaded OCSP response file %s (%zu bytes)",
              path,
              mgr->ocsp_response_len);
    return 0;
}

/* NSS key log format writer, consumed by Wireshark/tshark's
 * tls.keylog_file preference for offline decryption of captures. */
static void tls_keylog_callback(const SSL *ssl, const char *line)
{
    SSL_CTX *ctx;
    const char *path;
    FILE *f;

    ctx = SSL_get_SSL_CTX(ssl);
    if (!ctx)
        return;

    path = (const char *)SSL_CTX_get_app_data(ctx);
    if (!path || path[0] == '\0')
        return;

    f = fopen(path, "a");
    if (!f) {
        SEPP_ERROR("failed to open SSL key log file: %s", path);
        return;
    }

    fprintf(f, "%s\n", line);
    fclose(f);
}

static SSL_CTX *tls_new_ctx(const struct sepp_tls_config *config,
                            int server,
                            int require_client_certificate)
{
    SSL_CTX *ssl_ctx;
    int verify_mode;

    if (!config)
        return NULL;

    ssl_ctx = SSL_CTX_new(TLS_method());
    if (!ssl_ctx)
        return NULL;

    if (config->sslkeylogfile[0] != '\0') {
        /* app_data must outlive the SSL_CTX; config lives in the process's
         * static/heap-owned sepp_config_t for the daemon's lifetime. */
        SSL_CTX_set_app_data(ssl_ctx, (void *)config->sslkeylogfile);
        SSL_CTX_set_keylog_callback(ssl_ctx, tls_keylog_callback);
    }

    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);

    if (config->certificate[0] != '\0' &&
        SSL_CTX_use_certificate_file(ssl_ctx,
                                     config->certificate,
                                     SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    if (config->private_key[0] != '\0' &&
        SSL_CTX_use_PrivateKey_file(ssl_ctx,
                                    config->private_key,
                                    SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    if ((config->certificate[0] != '\0' ||
         config->private_key[0] != '\0') &&
        SSL_CTX_check_private_key(ssl_ctx) != 1) {
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    if (config->ca_bundle[0] != '\0' &&
        SSL_CTX_load_verify_locations(ssl_ctx,
                                      config->ca_bundle,
                                      NULL) != 1) {
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    if (server && require_client_certificate)
        verify_mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    else
        verify_mode = SSL_VERIFY_NONE;

    /* Certificate policy validation is delegated to the external verifier
     * after the TLS handshake.  FAIL_IF_NO_PEER_CERT still requires an
     * inbound client to present a certificate when configured. */
    SSL_CTX_set_verify(ssl_ctx, verify_mode, tls_verify_allow_cb);
    return ssl_ctx;
}

int sepp_tls_mgr_init(struct sepp_context *ctx, struct sepp_tls_mgr *mgr)
{
    if (!ctx || !mgr)
        return -1;

    memset(mgr, 0, sizeof(*mgr));
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    for (int i = 0; i < ctx->config.listener_count; i++) {
        const struct sepp_listener_config *listener =
            &ctx->config.listeners[i];

        mgr->server_ctx[listener->role] =
            tls_new_ctx(&listener->tls,
                        1,
                        listener->require_client_certificate);
        if (!mgr->server_ctx[listener->role]) {
            SEPP_ERROR("failed to initialize TLS context for %s listener",
                       sepp_listener_role_name(listener->role));
            goto fail;
        }
    }

    mgr->client_ctx = tls_new_ctx(&ctx->config.tls, 0, 0);
    if (!mgr->client_ctx)
        goto fail;

    if (tls_load_ocsp_response(ctx, mgr) != 0)
        goto fail;

    if (ctx->config.ocsp.server_stapling_enabled) {
        for (int role = SEPP_LISTENER_ROLE_INTERNAL_SBI;
             role < SEPP_LISTENER_ROLE_MAX;
             role++) {
            if (!mgr->server_ctx[role])
                continue;
            SSL_CTX_set_tlsext_status_cb(mgr->server_ctx[role], tls_status_cb);
            SSL_CTX_set_tlsext_status_arg(mgr->server_ctx[role], mgr);
        }
    }

    SEPP_INFO("TLS manager initialized");
    return 0;

fail:
    SEPP_ERROR("TLS manager initialization failed");
    sepp_tls_mgr_cleanup(mgr);
    return -1;
}

void sepp_tls_mgr_cleanup(struct sepp_tls_mgr *mgr)
{
    if (!mgr)
        return;

    for (int role = SEPP_LISTENER_ROLE_INTERNAL_SBI;
         role < SEPP_LISTENER_ROLE_MAX;
         role++) {
        if (mgr->server_ctx[role]) {
            SSL_CTX_free(mgr->server_ctx[role]);
            mgr->server_ctx[role] = NULL;
        }
    }

    if (mgr->client_ctx) {
        SSL_CTX_free(mgr->client_ctx);
        mgr->client_ctx = NULL;
    }

    free(mgr->ocsp_response);
    mgr->ocsp_response = NULL;
    mgr->ocsp_response_len = 0;

    EVP_cleanup();
}

static int tls_set_channel(struct sepp_conn *conn,
                           int is_server,
                           const char *expected_fqdn,
                           int external_cert_verify)
{
    struct sepp_tls_conn *tls;
    SSL_CTX *ssl_ctx;

    if (!conn || !conn->ctx)
        return -1;

    if (is_server) {
        if (conn->listener_role <= SEPP_LISTENER_ROLE_NONE ||
            conn->listener_role >= SEPP_LISTENER_ROLE_MAX)
            return -1;
        ssl_ctx = conn->ctx->tls_mgr.server_ctx[conn->listener_role];
    } else {
        ssl_ctx = conn->ctx->tls_mgr.client_ctx;
    }
    if (!ssl_ctx)
        return -1;

    tls = calloc(1, sizeof(*tls));
    if (!tls)
        return -1;
    sepp_object_counter_alloc(SEPP_OBJECT_TLS_CHANNEL);

    tls->ssl = SSL_new(ssl_ctx);
    if (!tls->ssl) {
        sepp_object_counter_free(SEPP_OBJECT_TLS_CHANNEL);
        free(tls);
        return -1;
    }

    tls->is_server = is_server;
    tls->external_cert_verify = external_cert_verify;
    sepp_cert_verify_req_init(&tls->verify_req);

    if (expected_fqdn)
        snprintf(tls->expected_fqdn, sizeof(tls->expected_fqdn), "%s", expected_fqdn);

    if (SSL_set_fd(tls->ssl, conn->fd) != 1) {
        SSL_free(tls->ssl);
        sepp_object_counter_free(SEPP_OBJECT_TLS_CHANNEL);
        free(tls);
        return -1;
    }

    if (!is_server && expected_fqdn && expected_fqdn[0] != '\0')
        SSL_set_tlsext_host_name(tls->ssl, expected_fqdn);

    if (!is_server && conn->ctx->config.ocsp.client_request_server_stapling)
        SSL_set_tlsext_status_type(tls->ssl, TLSEXT_STATUSTYPE_ocsp);

    if (is_server)
        SSL_set_accept_state(tls->ssl);
    else
        SSL_set_connect_state(tls->ssl);

    sepp_channel_cleanup(conn);
    conn->channel.ops = &tls_ops;
    conn->channel.priv = tls;
    conn->flags |= SEPP_CONN_F_TLS;
    conn->flags |= is_server ? SEPP_CONN_F_TLS_SERVER : SEPP_CONN_F_TLS_CLIENT;
    if (external_cert_verify)
        conn->flags |= SEPP_CONN_F_CERT_VERIFY;

    return 0;
}

int sepp_channel_set_tls_server(struct sepp_conn *conn)
{
    const struct sepp_listener_config *listener;
    int external_verify;

    if (!conn || !conn->ctx)
        return -1;

    listener = sepp_config_listener_by_role(&conn->ctx->config,
                                            conn->listener_role);
    if (!listener)
        return -1;

    external_verify = listener->external_certificate_verification;
    return tls_set_channel(conn, 1, NULL, external_verify);
}

int sepp_channel_set_tls_client(struct sepp_conn *conn,
                                const char *expected_fqdn,
                                int external_cert_verify)
{
    return tls_set_channel(conn, 0, expected_fqdn, external_cert_verify);
}

int sepp_tls_peer_matches_hostname(const struct sepp_conn *conn,
                                   const char *hostname)
{
    const struct sepp_tls_conn *tls;
    X509 *cert;
    int rc;

    if (!conn || !hostname || hostname[0] == '\0' ||
        !(conn->flags & SEPP_CONN_F_TLS) ||
        !(conn->flags & SEPP_CONN_F_ESTABLISHED) ||
        !conn->channel.priv)
        return -1;

    tls = conn->channel.priv;
    if (!tls->ssl || !tls->handshake_done)
        return -1;

    cert = SSL_get1_peer_certificate(tls->ssl);
    if (!cert)
        return -1;

    rc = X509_check_host(cert,
                         hostname,
                         0,
                         X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS,
                         NULL);
    X509_free(cert);

    if (rc == 1)
        return 1;
    if (rc == 0)
        return 0;

    return -1;
}
