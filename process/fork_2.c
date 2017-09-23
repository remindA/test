#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

int main()
{
    if(fork() == 0)
    {
        sleep(1);
        printf("child_1, pid=%d, ppid=%d\n", getpid(), getppid());
        exit(0);
    }

    if(fork() == 0)
    {
        sleep(2);
        printf("child_2, pid=%d, ppid=%d\n", getpid(), getppid());
        exit(0);
    }

    printf("father, pid=%d, ppid=%d\n", getpid(), getppid());
    sleep(3);
    return 0;
}
