#ifndef IPC_H
#define IPC_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "event.h"
#include "list.h"
#include "pending.h"

struct sepp_context;
struct sepp_ipc_client;
struct sepp_ipc_req;

#define SEPP_IPC_MAGIC 0x53495043u /* SIPC */
#define SEPP_IPC_VERSION 1u
#define SEPP_IPC_MAX_PAYLOAD 8192u

enum sepp_ipc_msg_type {
    SEPP_IPC_MSG_REQUEST = 1,
    SEPP_IPC_MSG_RESPONSE = 2,
    SEPP_IPC_MSG_CERT_VERIFY_REQ = 100,
    SEPP_IPC_MSG_CERT_VERIFY_RSP = 101,
};

struct sepp_ipc_msg_hdr {
    uint32_t magic;
    uint16_t version;
    uint16_t type;
    uint64_t request_id;
    uint32_t payload_len;
};

typedef void (*sepp_ipc_response_cb)(struct sepp_ipc_client *client,
                                     struct sepp_ipc_req *req,
                                     const void *payload,
                                     size_t payload_len,
                                     void *arg);

typedef void (*sepp_ipc_timeout_cb)(struct sepp_ipc_client *client,
                                    struct sepp_ipc_req *req,
                                    void *arg);

struct sepp_ipc_req {
    struct sepp_pending pending;
    struct sepp_ipc_client *client;
    struct sepp_list client_node;
    uint16_t response_type;
    sepp_ipc_response_cb response_cb;
    sepp_ipc_timeout_cb timeout_cb;
    void *arg;
};

struct sepp_ipc_client {
    struct sepp_context *ctx;
    struct event ev;
    int fd;
    struct sockaddr_un peer_addr;
    socklen_t peer_addr_len;
    struct sepp_list reqs;
};

void sepp_ipc_req_init(struct sepp_ipc_req *req);

int sepp_ipc_client_init(struct sepp_context *ctx,
                         struct sepp_ipc_client *client,
                         const char *local_path,
                         const char *peer_path);

void sepp_ipc_client_cleanup(struct sepp_ipc_client *client);

int sepp_ipc_send_request_type(struct sepp_ipc_client *client,
                               struct sepp_ipc_req *req,
                               uint16_t request_type,
                               uint16_t response_type,
                               const void *payload,
                               size_t payload_len,
                               uint64_t timeout_ms,
                               sepp_ipc_response_cb response_cb,
                               sepp_ipc_timeout_cb timeout_cb,
                               void *arg);

int sepp_ipc_send_request(struct sepp_ipc_client *client,
                          struct sepp_ipc_req *req,
                          const void *payload,
                          size_t payload_len,
                          uint64_t timeout_ms,
                          sepp_ipc_response_cb response_cb,
                          sepp_ipc_timeout_cb timeout_cb,
                          void *arg);

void sepp_ipc_cancel_request(struct sepp_ipc_client *client,
                             struct sepp_ipc_req *req);

#endif
