#ifndef EVENT_H
#define EVENT_H

#include <stdint.h>

struct event_ctx;
struct event;

typedef void (*event_cb)(struct event_ctx *ctx,
                         struct event *ev,
                         uint32_t events,
                         void *arg);

struct event {
    int fd;
    uint32_t events;
    event_cb cb;
    void *arg;
};

struct event_ctx {
    int epoll_fd;
    int stop;
    int event_count;
};

int event_ctx_init(struct event_ctx *ctx);
void event_ctx_destroy(struct event_ctx *ctx);

int event_add(struct event_ctx *ctx,
              struct event *ev,
              int fd,
              uint32_t events,
              event_cb cb,
              void *arg);

int event_mod(struct event_ctx *ctx,
              struct event *ev,
              uint32_t events);

int event_del(struct event_ctx *ctx,
              struct event *ev);

int event_loop(struct event_ctx *ctx);
void event_stop(struct event_ctx *ctx);

#endif
