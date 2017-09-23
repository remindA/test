#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


int main(int argc, char argv)
{
    printf("parent is %d\n", getpid());
    /*
    if(signal(SIGCHLD, sig_handle) == SIG_ERR)
    {
        perror("signal");
        exit(0);
    }
    */
    pid_t pid;
    int i = 0;
    for(i = 0; i < 3; i++)
    {
        pid = fork();
        if(pid < 0)
            perror("pid");
        else if(pid == 0)
            break;
        else
        {
            printf("deliver child_%d\n", pid);
        }
    }
    if(i == 0)
    {
        printf("===========ps=========\n");
        execlp("ps", "ps", NULL);
    }
    else if(i == 1)
    {
        printf("===========ls=========\n");
        execlp("ls", "ls", "-a", "-l", NULL);
    }
    else if(i == 2)
    {
        printf("===========seg=========\n");
        execl("./seg", "seg", NULL);
    }
    else
    {
        long int n = sleep(3); //设置了signal handle，sleep失效。
        int status;
        pid_t pid;
        while((pid = waitpid(0, &status, WNOHANG)) > 0)
        {
            if(WIFEXITED(status))
                printf("child_%d exit(%d)\n", pid, WEXITSTATUS(status));
            if(WIFSIGNALED(status))
                printf("child_%d dead signal:%d\n", pid, WTERMSIG(status));

        }
        printf("i == %d, pid=%d, n == %ld\n", i, getpid(), n);
    }
    return 0;
}

