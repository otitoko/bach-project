#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("otitoko");
MODULE_DESCRIPT("Kernel Module");
MODULE_VERSION("0.01");

static int __init basic_init(void){
    printk(KERN_INFO "hello world\n");
    return 0;
}

static void __exit basic_exit(void){
    printk(KERN_INFO "Exiting the world!\n");
}


module_init(basic_init);
module_init(basic_exit);
