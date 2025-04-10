#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

struct linux_dirent64 {
    ino64_t        d_ino;
    off64_t        d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[];
};

int main() {
    char buf[1024];
    int fd = open(".", O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    int nread = syscall(SYS_getdents64, fd, buf, sizeof(buf));
    if (nread < 0) {
        perror("getdents64");
        return 1;
    }

    printf("getdents64 returned %d bytes\n", nread);

    // Optional: print names from buffer
    int bpos = 0;
    while (bpos < nread) {
        struct linux_dirent64 *d = (struct linux_dirent64 *)(buf + bpos);
        printf("-> %s\n", d->d_name);
        bpos += d->d_reclen;
    }

    close(fd);
    return 0;
}

