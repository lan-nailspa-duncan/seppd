#include <stdio.h>
#include <time.h>
#include <stdarg.h>

#include "log.h"

static enum log_level current_level;

static const char *level_string[] =
{
    "ERROR",
    "WARN ",
    "INFO ",
    "DEBUG"
};

int log_init(enum log_level level)
{
    current_level = level;

    return 0;
}

void log_close(void)
{
}

void log_write(
        enum log_level level,
        const char *file,
        int line,
        const char *fmt,
        ...)
{
    va_list ap;
    time_t now;
    struct tm tm;

    if(level > current_level)
        return;

    now = time(NULL);

    localtime_r(&now, &tm);

    fprintf(stdout,
            "%04d-%02d-%02d %02d:%02d:%02d ",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec);

    fprintf(stdout,
            "[%s] %s:%d ",
            level_string[level],
            file,
            line);

    va_start(ap, fmt);

    vfprintf(stdout, fmt, ap);

    va_end(ap);

    fprintf(stdout,"\n");
}
