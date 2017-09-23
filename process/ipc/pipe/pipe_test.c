#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 注意pipefd[2]:
 *      pipefd[0]打开读
 *      pipefd[1]打开写
 */

int main()
{
    int fd[2];
    int ret = pipe(fd);
    if(ret < 0)
    {
        perror("pipe");
        exit(1);
    }

    printf("fd[0]=%d, fd[1]=%d\n", fd[0], fd[1]);
    pid_t pid = fork();
    if(pid < 0)
    {
        perror("fork");
        exit(1);
    }
    else if(pid > 0)
    {
        close(fd[0]);
        char *msg = "father send msg by pipe";
        ret = write(fd[1], msg, strlen(msg));
        if(ret < 0)
            perror("write");
        close(fd[1]);
    }
    else if(pid == 0)
    {
        close(fd[1]);
        char buf[1024] = {0};
        ret = read(fd[0], buf, sizeof(buf));
        if(ret < 0)
            perror("read");
        write(STDOUT_FILENO, buf, ret);
        close(fd[0]);
    }

    sleep(1);
    return 0;
}
