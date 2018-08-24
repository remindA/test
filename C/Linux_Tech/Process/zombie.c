#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char **argv)
{
    int i;
        pid_t pid = fork();
        switch(pid) {
            case 0:
                printf("i=%d\n", i);
                execl("/bin/cat", "cat", " worker >> txt", NULL);
                exit(0);
            case -1:
                perror("fork()");
                break;
            default:
                printf("worker %d\n", pid);
                break;
        }
    while(1);

    return 0;
}