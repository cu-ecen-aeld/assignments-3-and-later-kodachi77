# Variables
CROSS_COMPILE ?=
CC = $(CROSS_COMPILE)gcc
CFLAGS = -Wall -Wextra -Werror -O2
LDFLAGS = -s
LDLIBS =
TARGET = $(CROSS_COMPILE)writer
SRCS = writer.c
OBJS = $(SRCS:.c=.o)

# Default target: build the application
.PHONY: all
all: $(TARGET)

# Link the object files to create the final executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@

# Compile the C source files into object files
%.o: %.c
	$(CC) -c $(LDLAGS) $(LDLIBS) $^ -o $@

# Clean target: remove the application and object files
.PHONY: clean
clean:
	rm -f $(TARGET) $(OBJS)
