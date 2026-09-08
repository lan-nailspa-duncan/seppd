#ifndef N32C_H
#define N32C_H

struct sepp_conn;
struct sepp_context;
struct sepp_msg;
struct sepp_target_key;

int sepp_n32c_path_matches(const char *path);
int sepp_n32c_on_conn_ready(struct sepp_context *ctx,
                            struct sepp_conn *conn);
int sepp_n32c_handle_msg(struct sepp_context *ctx,
                         const struct sepp_msg *msg);
int sepp_n32c_start_tls_teardown(struct sepp_context *ctx,
                                 const struct sepp_target_key *key);

#endif /* N32C_H */
