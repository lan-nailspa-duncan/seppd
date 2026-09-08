#ifndef LISTENER_H
#define LISTENER_H

#include <stdint.h>

#include "config.h"
#include "event.h"

struct sepp_context;

struct sepp_listener {
    struct sepp_context *ctx;
    int fd;
    enum sepp_listener_role role;
    char address[64];
    uint16_t port;
    struct event ev;
};

int listener_start(struct sepp_context *ctx,
                   struct sepp_listener *listener,
                   const struct sepp_listener_config *config);

void listener_stop(struct event_ctx *events,
                   struct sepp_listener *listener);

#endif
