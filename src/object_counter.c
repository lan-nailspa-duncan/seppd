#include <errno.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include "log.h"
#include "object_counter.h"

static atomic_uint_fast64_t object_counters[SEPP_OBJECT_TYPE_COUNT];

static const char *const object_type_names[SEPP_OBJECT_TYPE_COUNT] = {
    [SEPP_OBJECT_PEER_CONTEXT] = "peer_context",
    [SEPP_OBJECT_CONNECTION] = "connection",
    [SEPP_OBJECT_STREAM_TRANSACTION] = "stream_transaction",
    [SEPP_OBJECT_TLS_CHANNEL] = "tls_channel",
    [SEPP_OBJECT_HTTP2_SESSION] = "http2_session",
    [SEPP_OBJECT_HTTP2_STREAM] = "http2_stream",
    [SEPP_OBJECT_HTTP2_OUT_BODY] = "http2_out_body",
    [SEPP_OBJECT_HTTP2_HEADER] = "http2_header",
    [SEPP_OBJECT_MIME_PART] = "mime_part",
    [SEPP_OBJECT_MIME_HEADER] = "mime_header",
};

static int object_type_valid(enum sepp_object_type type)
{
    return type >= 0 && type < SEPP_OBJECT_TYPE_COUNT;
}

void sepp_object_counter_alloc(enum sepp_object_type type)
{
    if (!object_type_valid(type)) {
        SEPP_ERROR("invalid object counter type %d on allocation", (int)type);
        return;
    }

    (void)atomic_fetch_add_explicit(&object_counters[type],
                                    1u,
                                    memory_order_relaxed);
}

void sepp_object_counter_free(enum sepp_object_type type)
{
    uint_fast64_t current;

    if (!object_type_valid(type)) {
        SEPP_ERROR("invalid object counter type %d on free", (int)type);
        return;
    }

    current = atomic_load_explicit(&object_counters[type],
                                   memory_order_relaxed);
    for (;;) {
        if (current == 0) {
            SEPP_ERROR("object counter underflow for type=%s",
                       sepp_object_type_name(type));
            return;
        }

        if (atomic_compare_exchange_weak_explicit(&object_counters[type],
                                                  &current,
                                                  current - 1u,
                                                  memory_order_relaxed,
                                                  memory_order_relaxed))
            return;
    }
}

uint64_t sepp_object_counter_get(enum sepp_object_type type)
{
    if (!object_type_valid(type))
        return 0;

    return (uint64_t)atomic_load_explicit(&object_counters[type],
                                          memory_order_relaxed);
}

const char *sepp_object_type_name(enum sepp_object_type type)
{
    if (!object_type_valid(type) || !object_type_names[type])
        return "unknown";

    return object_type_names[type];
}

void sepp_object_counters_dump(void)
{
    SEPP_INFO("live object counters begin");
    for (int i = 0; i < SEPP_OBJECT_TYPE_COUNT; i++) {
        enum sepp_object_type type = (enum sepp_object_type)i;

        SEPP_INFO("object-counter type=%s live=%" PRIu64,
                  sepp_object_type_name(type),
                  sepp_object_counter_get(type));
    }
    SEPP_INFO("live object counters end");
}

static void object_counter_signal_cb(struct event_ctx *events,
                                     struct event *ev,
                                     uint32_t event_flags,
                                     void *arg)
{
    struct sepp_object_counter_monitor *monitor = arg;

    (void)events;
    (void)ev;

    if (!monitor || !(event_flags & EPOLLIN))
        return;

    for (;;) {
        struct signalfd_siginfo info;
        ssize_t nread;

        nread = read(monitor->fd, &info, sizeof(info));
        if (nread == (ssize_t)sizeof(info)) {
            if (info.ssi_signo == SIGUSR2)
                sepp_object_counters_dump();
            continue;
        }

        if (nread < 0 && errno == EINTR)
            continue;

        if (nread < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return;

        if (nread < 0)
            SEPP_ERROR("object counter signalfd read failed: %s",
                       strerror(errno));
        else
            SEPP_ERROR("short object counter signalfd read: %zd", nread);
        return;
    }
}

int sepp_object_counter_monitor_init(
    struct event_ctx *events,
    struct sepp_object_counter_monitor *monitor)
{
    sigset_t mask;

    if (!events || !monitor)
        return -1;

    memset(monitor, 0, sizeof(*monitor));
    monitor->fd = -1;
    monitor->ev.fd = -1;

    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR2);
    if (sigprocmask(SIG_BLOCK, &mask, &monitor->previous_mask) != 0) {
        SEPP_ERROR("failed to block SIGUSR2: %s", strerror(errno));
        return -1;
    }
    monitor->mask_saved = 1;

    monitor->fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (monitor->fd < 0) {
        SEPP_ERROR("signalfd for SIGUSR2 failed: %s", strerror(errno));
        goto fail;
    }

    if (event_add(events,
                  &monitor->ev,
                  monitor->fd,
                  EPOLLIN,
                  object_counter_signal_cb,
                  monitor) != 0)
        goto fail;

    SEPP_INFO("object counter reporting enabled on SIGUSR2");
    return 0;

fail:
    sepp_object_counter_monitor_cleanup(events, monitor);
    return -1;
}

void sepp_object_counter_monitor_cleanup(
    struct event_ctx *events,
    struct sepp_object_counter_monitor *monitor)
{
    if (!monitor)
        return;

    if (events && monitor->ev.fd >= 0)
        (void)event_del(events, &monitor->ev);

    if (monitor->fd >= 0) {
        close(monitor->fd);
        monitor->fd = -1;
    }

    if (monitor->mask_saved) {
        if (sigprocmask(SIG_SETMASK, &monitor->previous_mask, NULL) != 0)
            SEPP_ERROR("failed to restore signal mask: %s", strerror(errno));
        monitor->mask_saved = 0;
    }
}
