#ifndef PENDING_H
#define PENDING_H

#include <stdint.h>

#include "list.h"
#include "timer.h"

struct sepp_context;
struct sepp_pending;

#define SEPP_PENDING_BUCKETS 256u
#define SEPP_PENDING_TIMEOUT_NONE 0u

typedef void (*sepp_pending_timeout_cb)(struct sepp_pending *pending,
                                        void *arg);

struct sepp_pending {
    uint64_t request_id;
    struct sepp_pending_mgr *mgr;
    struct sepp_timer timer;
    sepp_pending_timeout_cb timeout_cb;
    void *timeout_arg;
    struct sepp_list hash_node;
    int active;
};

struct sepp_pending_mgr {
    uint64_t next_request_id;
    struct sepp_list buckets[SEPP_PENDING_BUCKETS];
    unsigned int count;
};

void sepp_pending_init(struct sepp_pending *pending);
void sepp_pending_mgr_init(struct sepp_pending_mgr *mgr);
void sepp_pending_mgr_cleanup(struct sepp_context *ctx,
                              struct sepp_pending_mgr *mgr);

uint64_t sepp_pending_alloc_id(struct sepp_pending_mgr *mgr);

int sepp_pending_add(struct sepp_context *ctx,
                     struct sepp_pending_mgr *mgr,
                     struct sepp_pending *pending,
                     uint64_t request_id,
                     uint64_t timeout_ms,
                     sepp_pending_timeout_cb timeout_cb,
                     void *timeout_arg);

void sepp_pending_remove(struct sepp_context *ctx,
                         struct sepp_pending *pending);

struct sepp_pending *sepp_pending_lookup(struct sepp_pending_mgr *mgr,
                                         uint64_t request_id);

#endif
