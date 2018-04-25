#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

int main()
{
    int fd = open("test", O_RDWR | O_APPEND);
    if(fd < 0)
    {
        perror("open");
        exit(1);
    }
    if(fork() == 0)
    {
        write(fd, "child_1\n", 8);
        close(fd);
        printf("child_1, pid=%d, ppid=%d\n", getpid(), getppid());
        exit(0);
    }

    if(fork() == 0)
    {
        write(fd, "child_2\n", 8);
        close(fd);
        printf("child_2, pid=%d, ppid=%d\n", getpid(), getppid());
        exit(0);
    }

    write(fd, "father\n", 7);
    close(fd);
    printf("father, pid=%d, ppid=%d\n", getpid(), getppid());
    return 0;
}
