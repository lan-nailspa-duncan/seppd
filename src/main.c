#include <stdio.h>

#include "sepp.h"
#include "log.h"
#include "config.h"

int sepp_init(struct sepp_context *ctx)
{
    if (config_load("config/seppd.json", &ctx->config) != 0) {
        SEPP_ERROR("config load failed");
        return -1;
    }

    config_dump(&ctx->config);

    sepp_conn_table_init(&ctx->conn_table);
    sepp_stream_table_init(&ctx->stream_table);
    sepp_pending_mgr_init(&ctx->pending_mgr);
    sepp_msg_dispatcher_init(&ctx->msg_dispatcher);
    sepp_peer_table_init(&ctx->peer_table);

    if (sepp_peer_table_load_config(ctx, &ctx->peer_table) != 0) {
        SEPP_ERROR("peer table init failed");
        sepp_peer_table_cleanup(&ctx->peer_table);
        sepp_msg_dispatcher_cleanup(&ctx->msg_dispatcher);
        sepp_pending_mgr_cleanup(ctx, &ctx->pending_mgr);
        sepp_stream_table_destroy(ctx, &ctx->stream_table);
        sepp_conn_table_destroy(ctx, &ctx->conn_table);
        return -1;
    }

    if (sepp_n32_init(ctx) != 0) {
        SEPP_ERROR("N32 dispatcher init failed");
        sepp_peer_table_cleanup(&ctx->peer_table);
        sepp_msg_dispatcher_cleanup(&ctx->msg_dispatcher);
        sepp_pending_mgr_cleanup(ctx, &ctx->pending_mgr);
        sepp_stream_table_destroy(ctx, &ctx->stream_table);
        sepp_conn_table_destroy(ctx, &ctx->conn_table);
        return -1;
    }

    if (event_ctx_init(&ctx->events) != 0) {
        SEPP_ERROR("event context init failed");
        sepp_n32_cleanup(ctx);
        sepp_peer_table_cleanup(&ctx->peer_table);
        sepp_msg_dispatcher_cleanup(&ctx->msg_dispatcher);
        sepp_pending_mgr_cleanup(ctx, &ctx->pending_mgr);
        sepp_stream_table_destroy(ctx, &ctx->stream_table);
        sepp_conn_table_destroy(ctx, &ctx->conn_table);
        return -1;
    }

    if (sepp_object_counter_monitor_init(&ctx->events,
                                         &ctx->object_counter_monitor) != 0) {
        SEPP_ERROR("object counter monitor init failed");
        event_ctx_destroy(&ctx->events);
        sepp_n32_cleanup(ctx);
        sepp_peer_table_cleanup(&ctx->peer_table);
        sepp_msg_dispatcher_cleanup(&ctx->msg_dispatcher);
        sepp_pending_mgr_cleanup(ctx, &ctx->pending_mgr);
        sepp_stream_table_destroy(ctx, &ctx->stream_table);
        sepp_conn_table_destroy(ctx, &ctx->conn_table);
        return -1;
    }

    if (sepp_timer_mgr_init(ctx, &ctx->timer_mgr) != 0) {
        SEPP_ERROR("timer manager init failed");
        sepp_object_counter_monitor_cleanup(&ctx->events,
                                            &ctx->object_counter_monitor);
        event_ctx_destroy(&ctx->events);
        sepp_n32_cleanup(ctx);
        sepp_peer_table_cleanup(&ctx->peer_table);
        sepp_msg_dispatcher_cleanup(&ctx->msg_dispatcher);
        sepp_pending_mgr_cleanup(ctx, &ctx->pending_mgr);
        sepp_stream_table_destroy(ctx, &ctx->stream_table);
        sepp_conn_table_destroy(ctx, &ctx->conn_table);
        return -1;
    }

    if (sepp_cert_verify_client_init(ctx, &ctx->cert_verify) != 0) {
        SEPP_ERROR("certificate verifier init failed");
        sepp_cert_verify_client_cleanup(&ctx->cert_verify);
        sepp_timer_mgr_cleanup(ctx, &ctx->timer_mgr);
        sepp_object_counter_monitor_cleanup(&ctx->events,
                                            &ctx->object_counter_monitor);
        event_ctx_destroy(&ctx->events);
        sepp_n32_cleanup(ctx);
        sepp_peer_table_cleanup(&ctx->peer_table);
        sepp_msg_dispatcher_cleanup(&ctx->msg_dispatcher);
        sepp_pending_mgr_cleanup(ctx, &ctx->pending_mgr);
        sepp_stream_table_destroy(ctx, &ctx->stream_table);
        sepp_conn_table_destroy(ctx, &ctx->conn_table);
        return -1;
    }

    if (sepp_tls_mgr_init(ctx, &ctx->tls_mgr) != 0) {
        SEPP_ERROR("TLS manager init failed");
        sepp_cert_verify_client_cleanup(&ctx->cert_verify);
        sepp_timer_mgr_cleanup(ctx, &ctx->timer_mgr);
        sepp_object_counter_monitor_cleanup(&ctx->events,
                                            &ctx->object_counter_monitor);
        event_ctx_destroy(&ctx->events);
        sepp_n32_cleanup(ctx);
        sepp_peer_table_cleanup(&ctx->peer_table);
        sepp_msg_dispatcher_cleanup(&ctx->msg_dispatcher);
        sepp_pending_mgr_cleanup(ctx, &ctx->pending_mgr);
        sepp_stream_table_destroy(ctx, &ctx->stream_table);
        sepp_conn_table_destroy(ctx, &ctx->conn_table);
        return -1;
    }

    for (int i = 0; i < ctx->config.listener_count; i++) {
        if (listener_start(ctx,
                           &ctx->listeners[i],
                           &ctx->config.listeners[i]) != 0) {
            SEPP_ERROR("%s listener start failed",
                       sepp_listener_role_name(
                           ctx->config.listeners[i].role));
            for (int j = 0; j < i; j++)
                listener_stop(&ctx->events, &ctx->listeners[j]);
            sepp_tls_mgr_cleanup(&ctx->tls_mgr);
            sepp_cert_verify_client_cleanup(&ctx->cert_verify);
            sepp_timer_mgr_cleanup(ctx, &ctx->timer_mgr);
            sepp_object_counter_monitor_cleanup(&ctx->events,
                                                &ctx->object_counter_monitor);
            event_ctx_destroy(&ctx->events);
            sepp_n32_cleanup(ctx);
            sepp_peer_table_cleanup(&ctx->peer_table);
            sepp_msg_dispatcher_cleanup(&ctx->msg_dispatcher);
            sepp_pending_mgr_cleanup(ctx, &ctx->pending_mgr);
            sepp_stream_table_destroy(ctx, &ctx->stream_table);
            sepp_conn_table_destroy(ctx, &ctx->conn_table);
            return -1;
        }
    }

    return 0;
}

void sepp_destroy(struct sepp_context *ctx)
{
    if (!ctx)
        return;

    for (int i = 0; i < ctx->config.listener_count; i++)
        listener_stop(&ctx->events, &ctx->listeners[i]);
    sepp_conn_table_destroy(ctx, &ctx->conn_table);
    sepp_stream_table_destroy(ctx, &ctx->stream_table);
    sepp_n32_cleanup(ctx);
    sepp_peer_table_cleanup(&ctx->peer_table);
    sepp_msg_dispatcher_cleanup(&ctx->msg_dispatcher);
    sepp_tls_mgr_cleanup(&ctx->tls_mgr);
    sepp_cert_verify_client_cleanup(&ctx->cert_verify);
    sepp_pending_mgr_cleanup(ctx, &ctx->pending_mgr);
    sepp_timer_mgr_cleanup(ctx, &ctx->timer_mgr);
    sepp_object_counter_monitor_cleanup(&ctx->events,
                                        &ctx->object_counter_monitor);
    event_ctx_destroy(&ctx->events);
}

int main(void)
{
    struct sepp_context ctx;

    log_init(LOG_DEBUG);

    if (sepp_init(&ctx) != 0) {
        SEPP_ERROR("sepp init failed");
        return -1;
    }

    SEPP_INFO("SEPP daemon starting");

    if (event_loop(&ctx.events) != 0) {
        SEPP_ERROR("event loop failed");
        sepp_destroy(&ctx);
        log_close();
        return -1;
    }

    sepp_destroy(&ctx);
    log_close();

    return 0;
}
