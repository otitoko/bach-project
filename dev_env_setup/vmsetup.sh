qemu-system-x86_64 -m 2048 -smp 2 -enable-kvm -nic tap,ifname=tap0,script=no,downscript=no,model=virtio-net-pci -drive file=basedevimg.qcow2,format=qcow2

