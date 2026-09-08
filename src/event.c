#include <errno.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "event.h"
#include "log.h"

#define EVENT_MAX_EVENTS 64
#define EVENT_WAIT_TIMEOUT_MS -1

static void event_clear(struct event *ev)
{
    if (!ev)
        return;

    ev->fd = -1;
    ev->events = 0;
    ev->cb = NULL;
    ev->arg = NULL;
}

int event_ctx_init(struct event_ctx *ctx)
{
    if (!ctx)
        return -1;

    ctx->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (ctx->epoll_fd < 0) {
        SEPP_ERROR("epoll_create1 failed: %s", strerror(errno));
        return -1;
    }

    ctx->stop = 0;
    ctx->event_count = 0;

    SEPP_DEBUG("event context initialized");

    return 0;
}

void event_ctx_destroy(struct event_ctx *ctx)
{
    if (!ctx)
        return;

    if (ctx->epoll_fd >= 0) {
        close(ctx->epoll_fd);
        ctx->epoll_fd = -1;
    }

    ctx->stop = 1;
    ctx->event_count = 0;
}

int event_add(struct event_ctx *ctx,
              struct event *ev,
              int fd,
              uint32_t events,
              event_cb cb,
              void *arg)
{
    struct epoll_event ee;

    if (!ctx || !ev || fd < 0 || !cb)
        return -1;

    memset(&ee, 0, sizeof(ee));

    ev->fd = fd;
    ev->events = events;
    ev->cb = cb;
    ev->arg = arg;

    ee.events = events;
    ee.data.ptr = ev;

    if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ee) != 0) {
        SEPP_ERROR("epoll add fd %d failed: %s", fd, strerror(errno));
        event_clear(ev);
        return -1;
    }

    ctx->event_count++;

    return 0;
}

int event_mod(struct event_ctx *ctx,
              struct event *ev,
              uint32_t events)
{
    struct epoll_event ee;

    if (!ctx || !ev || ev->fd < 0 || !ev->cb)
        return -1;

    memset(&ee, 0, sizeof(ee));

    ev->events = events;

    ee.events = events;
    ee.data.ptr = ev;

    if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_MOD, ev->fd, &ee) != 0) {
        SEPP_ERROR("epoll mod fd %d failed: %s", ev->fd, strerror(errno));
        return -1;
    }

    return 0;
}

int event_del(struct event_ctx *ctx,
              struct event *ev)
{
    int fd;

    if (!ctx || !ev || ev->fd < 0)
        return -1;

    fd = ev->fd;

    if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, fd, NULL) != 0) {
        SEPP_ERROR("epoll del fd %d failed: %s", fd, strerror(errno));
        return -1;
    }

    event_clear(ev);

    if (ctx->event_count > 0)
        ctx->event_count--;

    return 0;
}

int event_loop(struct event_ctx *ctx)
{
    struct epoll_event events[EVENT_MAX_EVENTS];

    if (!ctx || ctx->epoll_fd < 0)
        return -1;

    if (ctx->event_count == 0) {
        SEPP_DEBUG("event loop skipped: no registered events");
        return 0;
    }

    SEPP_INFO("event loop started");

    while (!ctx->stop) {
        int n;

        n = epoll_wait(ctx->epoll_fd,
                       events,
                       EVENT_MAX_EVENTS,
                       EVENT_WAIT_TIMEOUT_MS);
        if (n < 0) {
            if (errno == EINTR)
                continue;

            SEPP_ERROR("epoll_wait failed: %s", strerror(errno));
            return -1;
        }

        for (int i = 0; i < n; i++) {
            struct event *ev = events[i].data.ptr;

            if (!ev || !ev->cb)
                continue;

            ev->cb(ctx, ev, events[i].events, ev->arg);

            if (ctx->stop)
                break;
        }
    }

    SEPP_INFO("event loop stopped");

    return 0;
}

void event_stop(struct event_ctx *ctx)
{
    if (!ctx)
        return;

    ctx->stop = 1;
}
