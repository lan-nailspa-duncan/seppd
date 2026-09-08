#ifndef OBJECT_COUNTER_H
#define OBJECT_COUNTER_H

#include <signal.h>
#include <stdint.h>

#include "event.h"

enum sepp_object_type {
    SEPP_OBJECT_PEER_CONTEXT = 0,
    SEPP_OBJECT_CONNECTION,
    SEPP_OBJECT_STREAM_TRANSACTION,
    SEPP_OBJECT_TLS_CHANNEL,
    SEPP_OBJECT_HTTP2_SESSION,
    SEPP_OBJECT_HTTP2_STREAM,
    SEPP_OBJECT_HTTP2_OUT_BODY,
    SEPP_OBJECT_HTTP2_HEADER,
    SEPP_OBJECT_MIME_PART,
    SEPP_OBJECT_MIME_HEADER,
    SEPP_OBJECT_TYPE_COUNT,
};

struct sepp_object_counter_monitor {
    int fd;
    struct event ev;
    sigset_t previous_mask;
    int mask_saved;
};

void sepp_object_counter_alloc(enum sepp_object_type type);
void sepp_object_counter_free(enum sepp_object_type type);
uint64_t sepp_object_counter_get(enum sepp_object_type type);
const char *sepp_object_type_name(enum sepp_object_type type);
void sepp_object_counters_dump(void);

int sepp_object_counter_monitor_init(
    struct event_ctx *events,
    struct sepp_object_counter_monitor *monitor);
void sepp_object_counter_monitor_cleanup(
    struct event_ctx *events,
    struct sepp_object_counter_monitor *monitor);

#endif /* OBJECT_COUNTER_H */
