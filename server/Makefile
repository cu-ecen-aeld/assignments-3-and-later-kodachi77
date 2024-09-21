# Variables
CROSS_COMPILE ?=
CC ?= $(CROSS_COMPILE)gcc
INSTALL ?= install
CFLAGS ?= -Wall -Wextra -Werror -O2 -Wno-maybe-uninitialized
LDFLAGS ?= -g -rdynamic
LDLIBS ?= -pthread -lrt
TARGET = aesdsocket
SRCS = aesdsocket.c hashmap.c thread_pool.c
OBJS = $(SRCS:.c=.o)

# Installation directory
INSTALL_DIR ?= /usr/bin

# Default target: build the application
all: $(TARGET)

# Link the object files to create the final executable
$(TARGET): $(OBJS)
	$(CC) $^ $(LDFLAGS) $(LDLIBS) -o $@ 
#	strip --strip-all $@

# Compile the C source files into object files
%.o: %.c
	$(CC) -c $(CFLAGS) $^ -o $@

# Clean target: remove the application and object files
clean:
	rm -f $(TARGET) $(OBJS)

# Install the writer app and scripts to /usr//bin
install: $(TARGET)
	$(INSTALL) -m 0755 $(TARGET) $(INSTALL_DIR)

.PHONY: all clean install
