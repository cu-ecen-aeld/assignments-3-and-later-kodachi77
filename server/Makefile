# Variables
CROSS_COMPILE ?=
CC ?= $(CROSS_COMPILE)gcc
INSTALL ?= install
CFLAGS ?= -Wall -Wextra -Werror -O2
LDFLAGS ?=
LDLIBS ?=
TARGET = aesdsocket
SRCS = aesdsocket.c
OBJS = $(SRCS:.c=.o)

# Installation directory
INSTALL_DIR ?= /usr/bin

# Default target: build the application
all: $(TARGET)

# Link the object files to create the final executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@

# Compile the C source files into object files
%.o: %.c
	$(CC) -c $(LDLAGS) $(LDLIBS) $^ -o $@

# Clean target: remove the application and object files
clean:
	rm -f $(TARGET) $(OBJS)

# Install the writer app and scripts to /bin
install: $(TARGET)
	$(INSTALL) -m 0755 $(TARGET) $(INSTALL_DIR)
	$(INSTALL) -m 0755 finder.sh $(INSTALL_DIR)
	$(INSTALL) -m 0755 finder-test.sh $(INSTALL_DIR)

.PHONY: all clean install
