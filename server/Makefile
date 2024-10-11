# Variables
CROSS_COMPILE ?=
CC ?= $(CROSS_COMPILE)gcc
INSTALL ?= install
CFLAGS ?= -Wall -Wextra -Werror -O2 -Wno-maybe-uninitialized
LDFLAGS ?= -g -rdynamic
LDLIBS ?= -pthread -lrt

# default target
TARGET = aesdsocket
SRCS = aesdsocket.c
OBJS = $(SRCS:.c=.o)

# additional target
TARGET_MULTI = aesdsocket_multi
SRCS_MULTI = aesdsocket_multi.c thread_pool.c hashmap.c
OBJS_MULTI = $(SRCS_MULTI:.c=.o)

MY_ARCH := $(shell $(CC) -dumpmachine | cut -d'-' -f1)

ifneq ($(MY_ARCH),x86_64)
	LDLIBS += -lexecinfo
endif

# Installation directory
INSTALL_DIR ?= /usr/bin

# Default target: build the application
all: $(TARGET) $(TARGET_MULTI)

# Link the object files to create the final executable
$(TARGET): $(OBJS)
	$(CC) $^ $(LDFLAGS) $(LDLIBS) -o $@ 

$(TARGET_MULTI): $(OBJS_MULTI)
	$(CC) $^ $(LDFLAGS) $(LDLIBS) -o $@ 

# Compile the C source files into object files
%.o: %.c
	$(CC) -c $(CFLAGS) $^ -o $@

# Clean target: remove the application and object files
clean:
	rm -f $(TARGET) $(OBJS) $(OBJS_MULTI) $(TARGET_MULTI)

# Install the writer app and scripts to /usr//bin
install: $(TARGET) $(TARGET_MULTI)
	$(INSTALL) -m 0755 $(TARGET) $(INSTALL_DIR)
	$(INSTALL) -m 0755 $(TARGET_MULTI) $(INSTALL_DIR)

.PHONY: all clean install
