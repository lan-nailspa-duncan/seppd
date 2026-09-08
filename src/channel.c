#include <errno.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "channel.h"
#include "connection.h"
#include "event.h"
#include "log.h"
#include "sepp.h"

#define SEPP_CHANNEL_READ_BUF_SIZE 4096

static int plain_tcp_finish_connect(struct sepp_conn *conn)
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
        SEPP_ERROR("outbound connection fd %d failed: %s",
                   conn->fd,
                   strerror(error));
        return -1;
    }

    conn->flags &= ~SEPP_CONN_F_CONNECTING;

    if (event_mod(&conn->ctx->events, &conn->ev, EPOLLIN | EPOLLRDHUP) != 0)
        return -1;

    SEPP_INFO("outbound connection fd %d established", conn->fd);

    return 0;
}

static ssize_t plain_tcp_read(struct sepp_conn *conn, void *buf, size_t len)
{
    return read(conn->fd, buf, len);
}

static ssize_t plain_tcp_write(struct sepp_conn *conn,
                               const void *buf,
                               size_t len)
{
    return write(conn->fd, buf, len);
}

static int plain_tcp_on_event(struct sepp_conn *conn, uint32_t event_flags)
{
    char buf[SEPP_CHANNEL_READ_BUF_SIZE];

    if ((conn->flags & SEPP_CONN_F_CONNECTING) &&
        (event_flags & EPOLLOUT)) {
        if (plain_tcp_finish_connect(conn) != 0)
            return -1;

        event_flags &= ~EPOLLOUT;
        if (event_flags == 0)
            return 0;
    }

    if (event_flags & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
        SEPP_INFO("plain TCP fd %d closed by event 0x%x",
                  conn->fd,
                  event_flags);
        return -1;
    }

    if (!(event_flags & EPOLLIN))
        return 0;

    for (;;) {
        ssize_t nread;

        nread = plain_tcp_read(conn, buf, sizeof(buf));
        if (nread > 0) {
            SEPP_DEBUG("plain TCP received %zd bytes on fd %d",
                       nread,
                       conn->fd);
            continue;
        }

        if (nread == 0) {
            SEPP_INFO("plain TCP fd %d closed by peer", conn->fd);
            return -1;
        }

        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;

        if (errno == EINTR)
            continue;

        SEPP_ERROR("plain TCP read on fd %d failed: %s",
                   conn->fd,
                   strerror(errno));
        return -1;
    }
}

static void plain_tcp_close(struct sepp_conn *conn)
{
    (void)conn;
}

static const struct sepp_channel_ops plain_tcp_ops = {
    .type = SEPP_CHANNEL_PLAIN_TCP,
    .name = "plain-tcp",
    .read = plain_tcp_read,
    .write = plain_tcp_write,
    .on_event = plain_tcp_on_event,
    .close = plain_tcp_close,
};

void sepp_channel_init(struct sepp_channel *channel)
{
    if (!channel)
        return;

    channel->ops = NULL;
    channel->priv = NULL;
}

void sepp_channel_cleanup(struct sepp_conn *conn)
{
    if (!conn)
        return;

    if (conn->channel.ops && conn->channel.ops->close)
        conn->channel.ops->close(conn);

    sepp_channel_init(&conn->channel);
}

int sepp_channel_set_plain_tcp(struct sepp_conn *conn)
{
    if (!conn)
        return -1;

    sepp_channel_cleanup(conn);
    conn->channel.ops = &plain_tcp_ops;
    conn->channel.priv = NULL;

    return 0;
}

ssize_t sepp_channel_read(struct sepp_conn *conn, void *buf, size_t len)
{
    if (!conn || !conn->channel.ops || !conn->channel.ops->read) {
        errno = ENOTCONN;
        return -1;
    }

    return conn->channel.ops->read(conn, buf, len);
}

ssize_t sepp_channel_write(struct sepp_conn *conn, const void *buf, size_t len)
{
    if (!conn || !conn->channel.ops || !conn->channel.ops->write) {
        errno = ENOTCONN;
        return -1;
    }

    return conn->channel.ops->write(conn, buf, len);
}

int sepp_channel_on_event(struct sepp_conn *conn, uint32_t events)
{
    if (!conn || !conn->channel.ops || !conn->channel.ops->on_event)
        return -1;

    return conn->channel.ops->on_event(conn, events);
}

const char *sepp_channel_name(const struct sepp_conn *conn)
{
    if (!conn || !conn->channel.ops || !conn->channel.ops->name)
        return "none";

    return conn->channel.ops->name;
}
