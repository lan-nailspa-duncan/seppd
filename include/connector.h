#ifndef CONNECTOR_H
#define CONNECTOR_H

#include <stdint.h>

#include "connection.h"

struct sepp_context;

struct sepp_conn *sepp_connector_get_or_connect_type(
    struct sepp_context *ctx,
    const struct sepp_target_key *target,
    const char *host,
    uint16_t port,
    enum sepp_conn_type type);

struct sepp_conn *sepp_connector_connect_n32f_replacement(
    struct sepp_context *ctx,
    const struct sepp_target_key *target,
    const char *host,
    uint16_t port);

#endif
