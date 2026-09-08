
#ifndef SEPP_H
#define SEPP_H

#include "config.h"
#include "daemon.h"
#include "event.h"
#include "log.h"
#include "listener.h"
#include "channel.h"
#include "connection.h"
#include "connector.h"
#include "stream.h"
#include "timer.h"
#include "pending.h"
#include "ipc.h"
#include "cert_verify.h"
#include "tls_channel.h"
#include "http2.h"
#include "sepp_msg.h"
#include "sbi.h"
#include "n32.h"
#include "object_counter.h"
#include "peer.h"
#include "routing.h"
#include "target_manager.h"

typedef struct sepp_context {

    struct sepp_config config;
    struct event_ctx events;
    struct sepp_object_counter_monitor object_counter_monitor;
    struct sepp_listener listeners[SEPP_CONFIG_MAX_LISTENERS];
    struct sepp_conn_table conn_table;
    struct sepp_stream_table stream_table;
    struct sepp_timer_mgr timer_mgr;
    struct sepp_pending_mgr pending_mgr;
    struct sepp_cert_verify_client cert_verify;
    struct sepp_tls_mgr tls_mgr;
    struct sepp_msg_dispatcher msg_dispatcher;
    struct sepp_peer_table peer_table;

} sepp_context_t;

int sepp_init(struct sepp_context *ctx);

void sepp_destroy(struct sepp_context *ctx);

#endif
