#ifndef CHANNEL_H
#define CHANNEL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct sepp_conn;

enum sepp_channel_type {
    SEPP_CHANNEL_NONE = 0,
    SEPP_CHANNEL_PLAIN_TCP,
    SEPP_CHANNEL_TLS,
};

struct sepp_channel_ops {
    enum sepp_channel_type type;
    const char *name;

    ssize_t (*read)(struct sepp_conn *conn, void *buf, size_t len);
    ssize_t (*write)(struct sepp_conn *conn, const void *buf, size_t len);
    int (*on_event)(struct sepp_conn *conn, uint32_t events);
    void (*close)(struct sepp_conn *conn);
};

struct sepp_channel {
    const struct sepp_channel_ops *ops;
    void *priv;
};

void sepp_channel_init(struct sepp_channel *channel);
void sepp_channel_cleanup(struct sepp_conn *conn);

int sepp_channel_set_plain_tcp(struct sepp_conn *conn);

ssize_t sepp_channel_read(struct sepp_conn *conn, void *buf, size_t len);
ssize_t sepp_channel_write(struct sepp_conn *conn, const void *buf, size_t len);
int sepp_channel_on_event(struct sepp_conn *conn, uint32_t events);

const char *sepp_channel_name(const struct sepp_conn *conn);

#endif
