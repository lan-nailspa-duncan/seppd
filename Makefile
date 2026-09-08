
CC      := gcc

OPENSSL_CFLAGS ?=
OPENSSL_LDFLAGS ?= -lssl -lcrypto
NGHTTP2_CFLAGS ?=
NGHTTP2_LDFLAGS ?= -lnghttp2
ZLIB_LDFLAGS ?= -lz

CFLAGS := -Wall -Wextra -Werror -std=c11 -g -Iinclude -D_POSIX_C_SOURCE=200809L $(OPENSSL_CFLAGS) $(NGHTTP2_CFLAGS)

LDFLAGS := -lcjson $(OPENSSL_LDFLAGS) $(NGHTTP2_LDFLAGS) $(ZLIB_LDFLAGS)

TARGET  := seppd

SRCS := \
    src/main.c \
    src/config.c \
    src/channel.c \
    src/cert_verify.c \
    src/connection.c \
    src/connector.c \
    src/daemon.c \
    src/event.c \
    src/http2.c \
    src/listener.c \
    src/mime.c \
    src/n32.c \
    src/n32c.c \
    src/n32f.c \
    src/object_counter.c \
    src/peer.c \
    src/routing.c \
    src/pending.c \
    src/ipc.c \
    src/stream.c \
    src/sepp_msg.c \
    src/sbi.c \
    src/timer.c \
    src/target.c \
    src/target_manager.c \
    src/tls_channel.c \
    src/log.c \
    src/util.c

OBJS := $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

clean:
	rm -f $(TARGET)
	rm -f $(OBJS)

.PHONY: all clean
