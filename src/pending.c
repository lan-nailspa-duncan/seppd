#include <stdint.h>
#include <string.h>

#include "log.h"
#include "pending.h"
#include "sepp.h"

static unsigned int sepp_pending_hash(uint64_t request_id)
{
    return (unsigned int)(request_id % SEPP_PENDING_BUCKETS);
}

void sepp_pending_init(struct sepp_pending *pending)
{
    if (!pending)
        return;

    pending->request_id = 0;
    pending->mgr = NULL;
    sepp_timer_init(&pending->timer);
    pending->timeout_cb = NULL;
    pending->timeout_arg = NULL;
    sepp_list_init(&pending->hash_node);
    pending->active = 0;
}

void sepp_pending_mgr_init(struct sepp_pending_mgr *mgr)
{
    if (!mgr)
        return;

    mgr->next_request_id = 1;
    mgr->count = 0;

    for (unsigned int i = 0; i < SEPP_PENDING_BUCKETS; i++)
        sepp_list_init(&mgr->buckets[i]);
}

static void sepp_pending_timeout(struct sepp_timer *timer, void *arg)
{
    struct sepp_pending *pending = arg;
    sepp_pending_timeout_cb cb;
    void *cb_arg;

    (void)timer;

    if (!pending || !pending->active)
        return;


    cb = pending->timeout_cb;
    cb_arg = pending->timeout_arg;

    if (!sepp_list_empty(&pending->hash_node)) {
        sepp_list_del(&pending->hash_node);
        if (pending->mgr && pending->mgr->count > 0)
            pending->mgr->count--;
    }

    pending->active = 0;
    pending->mgr = NULL;
    pending->timeout_cb = NULL;
    pending->timeout_arg = NULL;

    if (cb)
        cb(pending, cb_arg);
}

void sepp_pending_mgr_cleanup(struct sepp_context *ctx,
                              struct sepp_pending_mgr *mgr)
{
    if (!mgr)
        return;

    for (unsigned int i = 0; i < SEPP_PENDING_BUCKETS; i++) {
        struct sepp_list *pos;
        struct sepp_list *next;

        sepp_list_for_each_safe(pos, next, &mgr->buckets[i]) {
            struct sepp_pending *pending;

            pending = sepp_list_entry(pos, struct sepp_pending, hash_node);
            sepp_pending_remove(ctx, pending);
        }
    }

    mgr->count = 0;
}

uint64_t sepp_pending_alloc_id(struct sepp_pending_mgr *mgr)
{
    uint64_t id;

    if (!mgr)
        return 0;

    id = mgr->next_request_id++;
    if (mgr->next_request_id == 0)
        mgr->next_request_id = 1;

    return id;
}

int sepp_pending_add(struct sepp_context *ctx,
                     struct sepp_pending_mgr *mgr,
                     struct sepp_pending *pending,
                     uint64_t request_id,
                     uint64_t timeout_ms,
                     sepp_pending_timeout_cb timeout_cb,
                     void *timeout_arg)
{
    unsigned int bucket;

    if (!ctx || !mgr || !pending || request_id == 0)
        return -1;

    if (pending->active)
        return -1;

    if (sepp_pending_lookup(mgr, request_id))
        return -1;

    bucket = sepp_pending_hash(request_id);

    pending->request_id = request_id;
    pending->mgr = mgr;
    pending->timeout_cb = timeout_cb;
    pending->timeout_arg = timeout_arg;
    pending->active = 1;

    sepp_list_add_tail(&pending->hash_node, &mgr->buckets[bucket]);
    mgr->count++;

    if (timeout_ms != SEPP_PENDING_TIMEOUT_NONE && timeout_cb) {
        if (sepp_timer_start(ctx,
                             &pending->timer,
                             timeout_ms,
                             sepp_pending_timeout,
                             pending) != 0) {
            sepp_pending_remove(ctx, pending);
            return -1;
        }
    }

    return 0;
}

void sepp_pending_remove(struct sepp_context *ctx,
                         struct sepp_pending *pending)
{
    struct sepp_pending_mgr *mgr;

    if (!pending || !pending->active)
        return;

    mgr = pending->mgr;

    if (ctx && sepp_timer_active(&pending->timer))
        sepp_timer_stop(ctx, &pending->timer);
    else
        sepp_timer_init(&pending->timer);

    if (!sepp_list_empty(&pending->hash_node)) {
        sepp_list_del(&pending->hash_node);
        if (mgr && mgr->count > 0)
            mgr->count--;
    }

    pending->request_id = 0;
    pending->mgr = NULL;
    pending->timeout_cb = NULL;
    pending->timeout_arg = NULL;
    pending->active = 0;
}

struct sepp_pending *sepp_pending_lookup(struct sepp_pending_mgr *mgr,
                                         uint64_t request_id)
{
    struct sepp_list *pos;
    unsigned int bucket;

    if (!mgr || request_id == 0)
        return NULL;

    bucket = sepp_pending_hash(request_id);

    sepp_list_for_each(pos, &mgr->buckets[bucket]) {
        struct sepp_pending *pending;

        pending = sepp_list_entry(pos, struct sepp_pending, hash_node);
        if (pending->request_id == request_id)
            return pending;
    }

    return NULL;
}
