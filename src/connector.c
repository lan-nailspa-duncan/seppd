#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "connector.h"
#include "log.h"
#include "peer.h"
#include "sepp.h"
#include "tls_channel.h"

static int connector_set_nonblock(int fd)
{
    int flags;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return -1;

    return 0;
}

static int connector_set_cloexec(int fd)
{
    int flags;

    flags = fcntl(fd, F_GETFD, 0);
    if (flags < 0)
        return -1;

    if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0)
        return -1;

    return 0;
}

static int connector_prepare_fd(int fd)
{
    return connector_set_nonblock(fd) || connector_set_cloexec(fd);
}

static int connector_target_external_verify(struct sepp_context *ctx,
                                            const struct sepp_target_key *target)
{
    if (!ctx || !target)
        return 0;

    for (int i = 0; i < ctx->config.target_count; i++) {
        const struct sepp_target_config *cfg = &ctx->config.targets[i];
        struct sepp_target_key cfg_key;

        if (sepp_target_from_config(cfg, &cfg_key) != 0)
            continue;

        if (sepp_target_equal(&cfg_key, target))
            return cfg->external_certificate_verification;
    }

    return 0;
}

static struct sepp_conn *connector_try_addr(struct sepp_context *ctx,
                                            const struct sepp_target_key *target,
                                            const char *host,
                                            uint16_t port,
                                            enum sepp_conn_type type,
                                            const struct addrinfo *ai,
                                            uint32_t extra_flags)
{
    struct sockaddr_storage peer_addr;
    struct sepp_conn *conn;
    uint32_t flags = SEPP_CONN_F_OUTBOUND | extra_flags;
    int fd;
    int rc;

    fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0)
        return NULL;

    if (connector_prepare_fd(fd) != 0) {
        SEPP_ERROR("failed to prepare outbound fd %d: %s",
                   fd,
                   strerror(errno));
        close(fd);
        return NULL;
    }

    rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
    if (rc != 0) {
        if (errno != EINPROGRESS) {
            SEPP_ERROR("connect failed: %s", strerror(errno));
            close(fd);
            return NULL;
        }

        flags |= SEPP_CONN_F_CONNECTING;
    }

    memset(&peer_addr, 0, sizeof(peer_addr));
    memcpy(&peer_addr, ai->ai_addr, ai->ai_addrlen);

    conn = sepp_conn_add_socket(ctx,
                                fd,
                                &peer_addr,
                                ai->ai_addrlen,
                                flags);
    if (!conn) {
        close(fd);
        return NULL;
    }

    sepp_conn_set_type(conn, type);

    if (sepp_conn_set_target(&ctx->conn_table, conn, target) != 0) {
        sepp_conn_destroy(ctx, conn);
        return NULL;
    }

    if (sepp_channel_set_tls_client(conn,
                                    host,
                                    connector_target_external_verify(ctx, target)) != 0) {
        SEPP_ERROR("failed to attach TLS client channel to fd %d", fd);
        sepp_conn_destroy(ctx, conn);
        return NULL;
    }

    if (target->type == SEPP_TARGET_PEER_SEPP &&
        sepp_peer_attach_conn(&ctx->peer_table, conn) != 0) {
        SEPP_ERROR("failed to associate %s connection fd %d with peer %s:%u",
                   sepp_conn_type_name(type),
                   fd,
                   target->fqdn,
                   (unsigned int)port);
        sepp_conn_destroy(ctx, conn);
        return NULL;
    }

    if (flags & SEPP_CONN_F_CONNECTING)
        SEPP_INFO("outbound %s connection fd %d in progress",
                  sepp_conn_type_name(type),
                  fd);
    else
        SEPP_INFO("outbound %s connection fd %d established",
                  sepp_conn_type_name(type),
                  fd);

    return conn;
}

static struct sepp_conn *connector_connect_type(
    struct sepp_context *ctx,
    const struct sepp_target_key *target,
    const char *host,
    uint16_t port,
    enum sepp_conn_type type,
    uint32_t extra_flags)
{
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    struct addrinfo *rp;
    struct sepp_conn *conn;
    char portbuf[16];
    int rc;

    if (!ctx || !target || !host || port == 0 ||
        type == SEPP_CONN_TYPE_UNKNOWN)
        return NULL;

    SEPP_DEBUG("connector: dialing type=%s target_fqdn=%s host=%s port=%u",
               sepp_conn_type_name(type),
               target->fqdn,
               host,
               (unsigned int)port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    snprintf(portbuf, sizeof(portbuf), "%u", (unsigned int)port);

    rc = getaddrinfo(host, portbuf, &hints, &result);
    if (rc != 0) {
        SEPP_ERROR("getaddrinfo(%s:%u) failed: %s",
                   host,
                   (unsigned int)port,
                   gai_strerror(rc));
        return NULL;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        conn = connector_try_addr(ctx,
                                  target,
                                  host,
                                  port,
                                  type,
                                  rp,
                                  extra_flags);
        if (conn)
            break;
    }

    freeaddrinfo(result);

    return conn;
}

struct sepp_conn *sepp_connector_get_or_connect_type(
    struct sepp_context *ctx,
    const struct sepp_target_key *target,
    const char *host,
    uint16_t port,
    enum sepp_conn_type type)
{
    struct sepp_conn *conn;

    if (!ctx || !target || !host || port == 0 ||
        type == SEPP_CONN_TYPE_UNKNOWN)
        return NULL;

    conn = sepp_conn_lookup_target_type(&ctx->conn_table, target, type);
    if (conn) {
        SEPP_DEBUG("reusing %s connection fd %d for target %s",
                   sepp_conn_type_name(type),
                   conn->fd,
                   target->fqdn);
        return conn;
    }

    return connector_connect_type(ctx, target, host, port, type, 0);
}

struct sepp_conn *sepp_connector_connect_n32f_replacement(
    struct sepp_context *ctx,
    const struct sepp_target_key *target,
    const char *host,
    uint16_t port)
{
    if (!ctx || !target || target->type != SEPP_TARGET_PEER_SEPP ||
        !host || port == 0)
        return NULL;

    return connector_connect_type(ctx,
                                  target,
                                  host,
                                  port,
                                  SEPP_CONN_TYPE_N32F,
                                  SEPP_CONN_F_STANDBY);
}
