// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h>		// file_operations
#include "aesdchar.h"
#include "aesd_ioctl.h"

int aesd_major;			// use dynamic major
int aesd_minor;

MODULE_AUTHOR("kodachi77");
MODULE_LICENSE("Dual BSD/GPL");

static struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
	struct aesd_dev *dev;

	char *buf = kzalloc(PATH_MAX, GFP_KERNEL);

	if (unlikely(!buf))
		return -ENOMEM;

	PDEBUG("open '%s'; f_flags = 0x%x\n",
		file_path(filp, buf, PATH_MAX), filp->f_flags);

	kfree(buf);

	dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
	filp->private_data = dev;

	return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
	PDEBUG("release");
    /**
     * we don't need to do anything here.
     */
	return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
	ssize_t retval = 0;

	PDEBUG("read %zu bytes with offset %lld", count, *f_pos);

	struct aesd_dev *dev = filp->private_data;

	if (mutex_lock_interruptible(&dev->lock))
	    return -ERESTARTSYS;
	
	size_t offset = 0;
	struct aesd_buffer_entry *entry = NULL;

	entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->buffer, *f_pos, &offset);
	if (!entry) {
		retval = 0;	// we're done
		goto read_exit;
	}

	size_t bytes_left = entry->size - offset;
	size_t bytes_to_write = count > bytes_left ? bytes_left : count;

	//PDEBUG(">> %s", entry->buffptr + offset);

	size_t not_copied = copy_to_user(buf, entry->buffptr + offset, bytes_to_write);

	if (not_copied != 0) {
		retval = -EFAULT;
		goto read_exit;
	}

	retval = bytes_to_write;
	*f_pos += bytes_to_write;

 read_exit:
	mutex_unlock(&dev->lock);
	return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
	ssize_t retval = -ENOMEM;

	struct aesd_dev *dev = filp->private_data;

	PDEBUG("write %zu bytes with offset %lld", count, *f_pos);

	if (mutex_lock_interruptible(&dev->lock))
	    return -ERESTARTSYS;

	struct aesd_buffer_entry *entry = &dev->entry;

	void *new_buffptr = krealloc(entry->buffptr, entry->size + count, GFP_KERNEL);

	if (!new_buffptr) {
		retval = -ENOMEM;
		goto write_exit;
	}
	size_t not_copied = copy_from_user(new_buffptr + entry->size, buf, count);

	if (not_copied != 0) {
		// we don't need to free current block since we just allocated bigger chunk
		// and kept existing memory. We will zero it instead to prevent information
		// leaks.
		memset(new_buffptr + entry->size, 0, count);
		retval = -EFAULT;
		goto write_exit;
	}

	entry->buffptr = new_buffptr;
	entry->size += count;
	retval = count;

	//PHEXDUMP(entry->buffptr, entry->size);

	if (entry->buffptr[entry->size - 1] == '\n') {
		PDEBUG(">> %s", entry->buffptr);

		const char *entry_del = aesd_circular_buffer_add_entry(&dev->buffer, entry);

		memset(&aesd_device.entry, 0, sizeof(struct aesd_buffer_entry));
		if (entry_del)
			kfree(entry_del);
	}

	*f_pos += count; // aesd_circular_buffer_byte_count(&dev->buffer);

 write_exit:
	mutex_unlock(&dev->lock);
	return retval;
}

static loff_t aesd_llseek(struct file *filp, loff_t off, int whence)
{
    struct aesd_dev *dev = filp->private_data;
    loff_t new_pos = 0;
    size_t total_size;

	PDEBUG("llseek with offset: %lld", off);

    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    total_size = aesd_circular_buffer_byte_count(&dev->buffer);

    switch (whence) {
    case SEEK_SET:
        new_pos = off;
        break;
    case SEEK_CUR:
        new_pos = filp->f_pos + off;
        break;
    case SEEK_END:
        new_pos = total_size + off;
        break;
    default:
        mutex_unlock(&dev->lock);
        return -EINVAL;
    }

    if (new_pos < 0 || new_pos > total_size) {
        mutex_unlock(&dev->lock);
        return -EINVAL;
    }

    filp->f_pos = new_pos;
    mutex_unlock(&dev->lock);
    return new_pos;
}

static long aesd_unlocked_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct aesd_dev *dev = filp->private_data;
    struct aesd_seekto seekto;
    size_t total_size;
    int i, cmd_index;
    loff_t new_pos = 0;

	PDEBUG("ioctl with cmd: %d", cmd);

    if (_IOC_TYPE(cmd) != AESD_IOC_MAGIC) {
		pr_info("ioctl failed; magic # mismatch");
		return -ENOTTY;
	}
    if (_IOC_NR(cmd) > 1) {
		pr_info("ioctl failed; invalid command");
		return -ENOTTY;
	}

	if(cmd != AESDCHAR_IOCSEEKTO) {
		pr_info("ioctl failed; invalid command");
		return -ENOTTY;
	}

    if (copy_from_user(&seekto, (struct aesd_seekto __user *)arg, sizeof(seekto)))
        return -EFAULT;

    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    if (seekto.write_cmd >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED || 
        seekto.write_cmd < 0) {
        mutex_unlock(&dev->lock);
        return -EINVAL;
    }

    // Calculate the new file position based on the command and offset
    cmd_index = (dev->buffer.out_offs + seekto.write_cmd) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    if (seekto.write_cmd_offset >= dev->buffer.entry[cmd_index].size) {
        mutex_unlock(&dev->lock);
        return -EINVAL;
    }

	total_size = 0;
    for (i = 0; i < seekto.write_cmd; i++) {
    	int index = (dev->buffer.out_offs + i) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    	total_size += dev->buffer.entry[index].size;
	}
    new_pos = total_size + seekto.write_cmd_offset;

    filp->f_pos = new_pos;
    mutex_unlock(&dev->lock);
    return 0;
}

struct file_operations aesd_fops = {
	.owner = THIS_MODULE,
	.read = aesd_read,
	.write = aesd_write,
	.open = aesd_open,
	.llseek = aesd_llseek,
	.unlocked_ioctl = aesd_unlocked_ioctl, 
	.release = aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
	int err, devno = MKDEV(aesd_major, aesd_minor);

	cdev_init(&dev->cdev, &aesd_fops);
	dev->cdev.owner = THIS_MODULE;
	dev->cdev.ops = &aesd_fops;
	err = cdev_add(&dev->cdev, devno, 1);
	if (err) {
		printk(KERN_ERR "Error %d adding aesd cdev", err);
	}

	return err;
}

int aesd_init_module(void)
{
	PDEBUG("module init");
	dev_t dev = 0;
	int result;

	result = alloc_chrdev_region(&dev, aesd_minor, 1, "aesdchar");
	aesd_major = MAJOR(dev);
	if (result < 0) {
		printk(KERN_WARNING "Can't get major %d\n", aesd_major);
		return result;
	}
	memset(&aesd_device, 0, sizeof(struct aesd_dev));

	mutex_init(&aesd_device.lock);
	aesd_circular_buffer_init(&aesd_device.buffer);

	result = aesd_setup_cdev(&aesd_device);
	if (result) {
		unregister_chrdev_region(dev, 1);
	}
	return result;

}

void aesd_cleanup_module(void)
{
	PDEBUG("module exit");

	dev_t devno = MKDEV(aesd_major, aesd_minor);

	cdev_del(&aesd_device.cdev);

	uint8_t index;
	struct aesd_buffer_entry *entry;

	AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.buffer, index) {
		kfree(entry->buffptr);
	}
	mutex_destroy(&aesd_device.lock);

	unregister_chrdev_region(devno, 1);
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
