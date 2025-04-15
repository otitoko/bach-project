#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdio.h>

int main() {
    DIR *dir = opendir(".");
    if (!dir) {
        perror("Failed to open directory");
        return -1;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        printf("Found file: %s\n", entry->d_name);
    }

    closedir(dir);
    return 0;
}

