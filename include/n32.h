#ifndef N32_H
#define N32_H

struct sepp_context;
struct sepp_msg;

enum sepp_n32_operation {
    SEPP_N32_OP_UNKNOWN = 0,
    SEPP_N32C_OP_EXCHANGE_CAPABILITY,
    SEPP_N32C_OP_N32F_TERMINATE,
    SEPP_N32C_OP_N32F_ERROR,
    SEPP_N32F_OP_NSMF_PDUSESSION,
};

const char *sepp_n32_operation_name(enum sepp_n32_operation op);

int sepp_n32_init(struct sepp_context *ctx);
void sepp_n32_cleanup(struct sepp_context *ctx);

#endif /* N32_H */
