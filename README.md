#LKM Rootkit using the ftrace method for hooking.

###Execution flow(more or less):

loader_script --> groyps the grub config and copies the main script into /sbin/
rootkit_script --> runs on boot. checks for missing files and downloads xmrig as necessary. starts xmrig and hides it via kill hook. 


Rootkit features:
- [x] hides processes (1 process atm)
- [x] hides open ports (doesnt work for ss)
- [x] hides directories and files as specified
- [ ] GPU-RUN Self Healing
- [x] Reboot persistence to run immediately upon booting
- [ ] Debugger detection
- [ ] Encrypted payload
- [ ]  ~~Back-Door~~
