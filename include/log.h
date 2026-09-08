#ifndef LOG_H
#define LOG_H

#include <stdarg.h>

enum log_level
{
    LOG_ERROR = 0,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG
};

int log_init(enum log_level level);

void log_close(void);

void log_write(
        enum log_level level,
        const char *file,
        int line,
        const char *fmt,
        ...);

#define SEPP_ERROR(...) \
    log_write(LOG_ERROR,__FILE__,__LINE__,__VA_ARGS__)

#define SEPP_WARN(...) \
    log_write(LOG_WARN,__FILE__,__LINE__,__VA_ARGS__)

#define SEPP_INFO(...) \
    log_write(LOG_INFO,__FILE__,__LINE__,__VA_ARGS__)

#define SEPP_DEBUG(...) \
    log_write(LOG_DEBUG,__FILE__,__LINE__,__VA_ARGS__)

#endif
