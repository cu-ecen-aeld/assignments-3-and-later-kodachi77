/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer imlementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#include "aesd-circular-buffer.h"

/**
 * @param buffer the buffer to search for corresponding offset.  Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
            size_t char_offset, size_t *entry_offset_byte_rtn )
{
    size_t cumulative_size = 0;
    size_t current_offset = buffer->out_offs;
    size_t entry_index = 0;

    // Iterate through the buffer entries
    while (entry_index < buffer->count) {
        struct aesd_buffer_entry *entry = &buffer->entry[current_offset];

        // Check if the char_offset falls within the current entry
        if (cumulative_size + entry->size > char_offset) {
            // Calculate the offset within the entry
            *entry_offset_byte_rtn = char_offset - cumulative_size;
            return entry;
        }

        // Update the cumulative size
        cumulative_size += entry->size;

        // Move to the next entry
        current_offset = (current_offset + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
        entry_index++;
    }

    // If we reach here, the char_offset is not available in the buffer
    return NULL;
}

/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/
void aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    // Add the new entry at the in_offs position
    memcpy(&buffer->entry[buffer->in_offs], add_entry, sizeof(struct aesd_buffer_entry));

    // Advance in_offs to the next position
    buffer->in_offs = (buffer->in_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;    

    // Check if the buffer is full
    if (buffer->count == AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED) {
        buffer->full = true;
    } else {
        // Buffer is not full, increment the count
        buffer->count++;
    }

    if(buffer->full) {
        // Buffer is full, advance out_offs to overwrite the oldest entry
        buffer->out_offs = (buffer->out_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer, 0, sizeof(struct aesd_circular_buffer));
}
