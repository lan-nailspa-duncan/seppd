#ifndef N32F_H
#define N32F_H

struct sepp_context;
struct sepp_msg;

int sepp_n32f_handle_msg(struct sepp_context *ctx,
                         const struct sepp_msg *msg);

#endif /* N32F_H */
