LKM Rootkit using the ftrace method for hooking.

Execution flow(more or less):

init_script --> downloads xmrig binary
|
xmrig_script --> runs xmrig with the correct settings such as 20% threads
|
rootkit_script --> compiles via Makefile the rootkit and runs the rootkit.

could and probably should be all one script

Rootkit features:
+hides processes (1 process atm)
+hides open ports (doesnt work for ss)
+hides directories and files as specified

TO BE IMPLEMENTED:
-Back-Door
-GPU-RUN Self Healing
-Reboot persistence to run immediately upon booting
-Debugger detection
-Encrypted payload
