#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char **argv)
{
    pid_t pid;
    printf("-----\n");
    pid = fork();
    if(pid == 0)
    {
        int fd = open("ps.txt", O_CREAT | O_RDWR);
        dup2(fd, 1);
        execl("/bin/ps", "ps", "aux", NULL);
        close(fd);
    }
    else if(pid > 0)
    {
        sleep(1);
    }

    return 0;

}
