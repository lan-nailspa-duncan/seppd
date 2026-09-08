#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#include "log.h"
#include "sepp.h"
#include "timer.h"

#define SEPP_TIMER_INITIAL_CAP 16u

uint64_t sepp_time_now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;

    return ((uint64_t)ts.tv_sec * 1000u) + ((uint64_t)ts.tv_nsec / 1000000u);
}

void sepp_timer_init(struct sepp_timer *timer)
{
    if (!timer)
        return;

    timer->expire_ms = 0;
    timer->cb = NULL;
    timer->arg = NULL;
    timer->active = 0;
    timer->heap_idx = SEPP_TIMER_HEAP_NONE;
}

static int timer_less(const struct sepp_timer *a,
                      const struct sepp_timer *b)
{
    return a->expire_ms < b->expire_ms;
}

static void timer_heap_swap(struct sepp_timer_mgr *mgr, size_t a, size_t b)
{
    struct sepp_timer *tmp;

    tmp = mgr->heap[a];
    mgr->heap[a] = mgr->heap[b];
    mgr->heap[b] = tmp;

    mgr->heap[a]->heap_idx = a;
    mgr->heap[b]->heap_idx = b;
}

static void timer_heap_sift_up(struct sepp_timer_mgr *mgr, size_t idx)
{
    while (idx > 0) {
        size_t parent = (idx - 1u) / 2u;

        if (!timer_less(mgr->heap[idx], mgr->heap[parent]))
            break;

        timer_heap_swap(mgr, idx, parent);
        idx = parent;
    }
}

static void timer_heap_sift_down(struct sepp_timer_mgr *mgr, size_t idx)
{
    for (;;) {
        size_t left = (idx * 2u) + 1u;
        size_t right = left + 1u;
        size_t smallest = idx;

        if (left < mgr->heap_len &&
            timer_less(mgr->heap[left], mgr->heap[smallest]))
            smallest = left;

        if (right < mgr->heap_len &&
            timer_less(mgr->heap[right], mgr->heap[smallest]))
            smallest = right;

        if (smallest == idx)
            break;

        timer_heap_swap(mgr, idx, smallest);
        idx = smallest;
    }
}

static int timer_heap_reserve(struct sepp_timer_mgr *mgr, size_t need)
{
    struct sepp_timer **new_heap;
    size_t new_cap;

    if (mgr->heap_cap >= need)
        return 0;

    new_cap = mgr->heap_cap ? mgr->heap_cap : SEPP_TIMER_INITIAL_CAP;
    while (new_cap < need)
        new_cap *= 2u;

    new_heap = realloc(mgr->heap, new_cap * sizeof(*new_heap));
    if (!new_heap)
        return -1;

    mgr->heap = new_heap;
    mgr->heap_cap = new_cap;

    return 0;
}

static int timer_heap_push(struct sepp_timer_mgr *mgr,
                           struct sepp_timer *timer)
{
    if (timer_heap_reserve(mgr, mgr->heap_len + 1u) != 0)
        return -1;

    timer->heap_idx = mgr->heap_len;
    mgr->heap[mgr->heap_len] = timer;
    mgr->heap_len++;

    timer_heap_sift_up(mgr, timer->heap_idx);

    return 0;
}

static void timer_heap_remove(struct sepp_timer_mgr *mgr,
                              struct sepp_timer *timer)
{
    size_t idx;
    size_t last;

    if (!mgr || !timer || !timer->active ||
        timer->heap_idx == SEPP_TIMER_HEAP_NONE ||
        timer->heap_idx >= mgr->heap_len)
        return;

    idx = timer->heap_idx;
    last = mgr->heap_len - 1u;

    if (idx != last) {
        mgr->heap[idx] = mgr->heap[last];
        mgr->heap[idx]->heap_idx = idx;
    }

    mgr->heap_len--;

    timer->active = 0;
    timer->heap_idx = SEPP_TIMER_HEAP_NONE;

    if (idx < mgr->heap_len) {
        timer_heap_sift_down(mgr, idx);
        timer_heap_sift_up(mgr, idx);
    }
}

static struct sepp_timer *timer_heap_pop(struct sepp_timer_mgr *mgr)
{
    struct sepp_timer *timer;

    if (!mgr || mgr->heap_len == 0)
        return NULL;

    timer = mgr->heap[0];
    timer_heap_remove(mgr, timer);

    return timer;
}

static int timer_mgr_arm(struct sepp_timer_mgr *mgr)
{
    struct itimerspec its;
    uint64_t now;
    uint64_t delay_ms;

    if (!mgr || mgr->ev.fd < 0)
        return -1;

    memset(&its, 0, sizeof(its));

    if (mgr->heap_len > 0) {
        now = sepp_time_now_ms();
        delay_ms = 1;

        if (mgr->heap[0]->expire_ms > now)
            delay_ms = mgr->heap[0]->expire_ms - now;

        its.it_value.tv_sec = (time_t)(delay_ms / 1000u);
        its.it_value.tv_nsec = (long)((delay_ms % 1000u) * 1000000u);
    }

    if (timerfd_settime(mgr->ev.fd, 0, &its, NULL) != 0) {
        SEPP_ERROR("timerfd_settime failed: %s", strerror(errno));
        return -1;
    }

    return 0;
}

static int timerfd_drain(int fd)
{
    for (;;) {
        uint64_t expirations;
        ssize_t nread;

        nread = read(fd, &expirations, sizeof(expirations));
        if (nread == (ssize_t)sizeof(expirations))
            continue;

        if (nread < 0 && errno == EINTR)
            continue;

        if (nread < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return 0;

        if (nread < 0) {
            SEPP_ERROR("timerfd read failed: %s", strerror(errno));
            return -1;
        }

        return 0;
    }
}

static void timer_event_cb(struct event_ctx *events,
                           struct event *ev,
                           uint32_t event_flags,
                           void *arg)
{
    struct sepp_context *ctx = arg;
    struct sepp_timer_mgr *mgr;
    uint64_t now;

    (void)events;
    (void)ev;

    if (!ctx)
        return;

    mgr = &ctx->timer_mgr;

    if (event_flags & (EPOLLERR | EPOLLHUP)) {
        SEPP_ERROR("timerfd event error: 0x%x", event_flags);
        return;
    }

    if (!(event_flags & EPOLLIN))
        return;

    if (timerfd_drain(mgr->ev.fd) != 0)
        return;

    now = sepp_time_now_ms();

    while (mgr->heap_len > 0 && mgr->heap[0]->expire_ms <= now) {
        struct sepp_timer *timer;
        sepp_timer_cb cb;
        void *cb_arg;

        timer = timer_heap_pop(mgr);
        if (!timer)
            break;

        cb = timer->cb;
        cb_arg = timer->arg;

        timer->cb = NULL;
        timer->arg = NULL;

        if (cb)
            cb(timer, cb_arg);

        now = sepp_time_now_ms();
    }

    (void)timer_mgr_arm(mgr);
}

int sepp_timer_mgr_init(struct sepp_context *ctx,
                        struct sepp_timer_mgr *mgr)
{
    int fd;

    if (!ctx || !mgr)
        return -1;

    memset(mgr, 0, sizeof(*mgr));
    mgr->ev.fd = -1;

    fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (fd < 0) {
        SEPP_ERROR("timerfd_create failed: %s", strerror(errno));
        return -1;
    }

    if (event_add(&ctx->events,
                  &mgr->ev,
                  fd,
                  EPOLLIN,
                  timer_event_cb,
                  ctx) != 0) {
        close(fd);
        mgr->ev.fd = -1;
        return -1;
    }

    SEPP_DEBUG("timer manager initialized");

    return 0;
}

void sepp_timer_mgr_cleanup(struct sepp_context *ctx,
                            struct sepp_timer_mgr *mgr)
{
    int fd;

    if (!mgr)
        return;

    fd = mgr->ev.fd;

    if (ctx && mgr->ev.fd >= 0)
        event_del(&ctx->events, &mgr->ev);

    if (fd >= 0)
        close(fd);

    mgr->ev.fd = -1;

    for (size_t i = 0; i < mgr->heap_len; i++)
        sepp_timer_init(mgr->heap[i]);

    free(mgr->heap);
    mgr->heap = NULL;
    mgr->heap_len = 0;
    mgr->heap_cap = 0;
}

int sepp_timer_start(struct sepp_context *ctx,
                     struct sepp_timer *timer,
                     uint64_t timeout_ms,
                     sepp_timer_cb cb,
                     void *arg)
{
    struct sepp_timer_mgr *mgr;

    if (!ctx || !timer || !cb)
        return -1;

    mgr = &ctx->timer_mgr;

    if (timer->active)
        sepp_timer_stop(ctx, timer);

    timer->expire_ms = sepp_time_now_ms() + timeout_ms;
    timer->cb = cb;
    timer->arg = arg;
    timer->active = 1;

    if (timer_heap_push(mgr, timer) != 0) {
        sepp_timer_init(timer);
        return -1;
    }

    if (timer_mgr_arm(mgr) != 0) {
        timer_heap_remove(mgr, timer);
        sepp_timer_init(timer);
        return -1;
    }

    return 0;
}

void sepp_timer_stop(struct sepp_context *ctx,
                     struct sepp_timer *timer)
{
    struct sepp_timer_mgr *mgr;

    if (!ctx || !timer || !timer->active)
        return;

    mgr = &ctx->timer_mgr;
    timer_heap_remove(mgr, timer);
    sepp_timer_init(timer);

    (void)timer_mgr_arm(mgr);
}

int sepp_timer_active(const struct sepp_timer *timer)
{
    return timer && timer->active;
}
