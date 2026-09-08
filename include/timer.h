#ifndef TIMER_H
#define TIMER_H

#include <stddef.h>
#include <stdint.h>

#include "event.h"

struct sepp_context;
struct sepp_timer;

typedef void (*sepp_timer_cb)(struct sepp_timer *timer, void *arg);

#define SEPP_TIMER_HEAP_NONE ((size_t)-1)

struct sepp_timer {
    uint64_t expire_ms;
    sepp_timer_cb cb;
    void *arg;
    int active;
    size_t heap_idx;
};

struct sepp_timer_mgr {
    struct event ev;
    struct sepp_timer **heap;
    size_t heap_len;
    size_t heap_cap;
};

void sepp_timer_init(struct sepp_timer *timer);

int sepp_timer_mgr_init(struct sepp_context *ctx,
                        struct sepp_timer_mgr *mgr);

void sepp_timer_mgr_cleanup(struct sepp_context *ctx,
                            struct sepp_timer_mgr *mgr);

int sepp_timer_start(struct sepp_context *ctx,
                     struct sepp_timer *timer,
                     uint64_t timeout_ms,
                     sepp_timer_cb cb,
                     void *arg);

void sepp_timer_stop(struct sepp_context *ctx,
                     struct sepp_timer *timer);

int sepp_timer_active(const struct sepp_timer *timer);

uint64_t sepp_time_now_ms(void);

#endif
