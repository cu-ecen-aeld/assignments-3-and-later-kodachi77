// SPDX-License-Identifier: GPL-2.0-or-later
/**
 *  Created on: March 1st, 2020
 *      Author: Dan Walkes
 */

#ifndef AESD_CIRCULAR_BUFFER_H
#define AESD_CIRCULAR_BUFFER_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stddef.h>		// size_t
#include <stdint.h>		// uintx_t
#include <stdbool.h>
#endif

// As a side note: non-power-of-2 length is significantly slower because it requires
// modulo operator instead of much faster bitwise-AND for determining occupancy or
// remaining capacity of the buffer.
#define AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED 10

struct aesd_buffer_entry {
    /**
     * A location where the buffer contents in buffptr are stored
     */
	const char *buffptr;
    /**
     * Number of bytes stored in buffptr
     */
	size_t size;
};

struct aesd_circular_buffer {
    /**
     * An array of pointers to memory allocated for the most recent write operations
     */
	struct aesd_buffer_entry entry[AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED];
    /**
     * The current location in the entry structure where the next write should
     * be stored.
     */
	uint8_t in_offs;
    /**
     * The first location in the entry structure to read from
     */
	uint8_t out_offs;
    /**
     * set to true when the buffer entry structure is full
     */
	bool full;
    /**
     * The number of entries in the buffer
     */
	uint8_t count;
};

extern struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct
										 aesd_circular_buffer
										 *buffer,
										 size_t
										 char_offset,
										 size_t
										 *entry_offset_byte_rtn);

extern const char *aesd_circular_buffer_add_entry(struct aesd_circular_buffer
						  *buffer, const struct aesd_buffer_entry
						  *add_entry);

extern void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer);

extern size_t aesd_circular_buffer_byte_count(struct aesd_circular_buffer *buffer);

/**
 * Create a for loop to iterate over each member of the circular buffer.
 * Useful when you've allocated memory for circular buffer entries and need to free it
 * @param entryptr is a struct aesd_buffer_entry* to set with the current entry
 * @param buffer is the struct aesd_buffer * describing the buffer
 * @param index is a uint8_t stack allocated value used by this macro for an index
 * Example usage:
 * uint8_t index;
 * struct aesd_circular_buffer buffer;
 * struct aesd_buffer_entry *entry;
 * AESD_CIRCULAR_BUFFER_FOREACH(entry, &buffer, index) {
 *      free(entry->buffptr);
 * }
 */
#define AESD_CIRCULAR_BUFFER_FOREACH(entryptr, buffer, index) \
    for (index = 0, entryptr =  &((buffer)->entry[index]); \
	    index < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; \
	    index++, entryptr =  &((buffer)->entry[index]))

#endif				/* AESD_CIRCULAR_BUFFER_H */
