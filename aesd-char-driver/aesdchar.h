// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * aesdchar.h
 *
 *  Created on: Oct 23, 2019
 *      Author: Dan Walkes
 */

#ifndef AESD_CHAR_DRIVER_AESDCHAR_H_
#define AESD_CHAR_DRIVER_AESDCHAR_H_

#include <linux/mutex.h>
#include <linux/cdev.h>

#include "aesd-circular-buffer.h"

#ifdef __KERNEL__
#include <linux/ratelimit.h>

//#define USE_FTRACE_BUFFER
#undef USE_FTRACE_BUFFER

#ifdef USE_FTRACE_BUFFER
#define DBGPRINT(string, args...)                                       \
    trace_printk(string, ##args)
#else
#define DBGPRINT(string, args...) do {                                  \
    int USE_RATELIMITING = 0;                                           \
    if (USE_RATELIMITING) {                                             \
	pr_info_ratelimited(string, ##args);                            \
    }                                                                   \
    else                                                                \
	pr_info(string, ##args);                                        \
} while (0)
#endif
#endif

#define AESD_DEBUG 1		// Remove comment on this line to enable debug

#undef PDEBUG			/* undef it, just in case */
#ifdef AESD_DEBUG
#ifdef __KERNEL__
     /* This one if debugging is on, and kernel space */
#define PDEBUG(fmt, args...) do { \
	DBGPRINT("aesdchar:%s:%d: " fmt, __func__, __LINE__, ##args); \
} while (0)
#else
     /* This one for user space */
#define PDEBUG(string, args...) do {                                       \
    fprintf(stderr, "aesdchar:%s:%d: " fmt, __func__, __LINE__, ##args);     \
} while (0)
#endif
#else
#define PDEBUG(fmt, args...)	/* not debugging: nothing */
#endif

#ifdef __KERNEL__
#define assert(expr) do {                               \
if (!(expr)) {                                          \
    pr_warn("*** ASSERT [%s] failed! : aesdchar:%s:%s:%d ***\n", \
    #expr, __FILE__, __func__, __LINE__);               \
}                                                       \
} while (0)
#endif

#ifdef __KERNEL__
#ifdef AESD_DEBUG
#define PHEXDUMP(from_addr, len) do {                                    \
    print_hex_dump_bytes("aesdchar: ", DUMP_PREFIX_ADDRESS, from_addr, len);     \
} while (0)
#else
#define PHEXDUMP(from_addr, len)
#endif
#else
#define PHEXDUMP(from_addr, len)
#endif

struct aesd_dev {
	struct mutex lock;
	struct aesd_circular_buffer buffer;
	struct aesd_buffer_entry entry;
	struct cdev cdev;	/* Char device structure      */
};

#endif				/* AESD_CHAR_DRIVER_AESDCHAR_H_ */
