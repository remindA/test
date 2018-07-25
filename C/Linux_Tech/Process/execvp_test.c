#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

int main(int argc, char **argv)
{
    char **ps_argv = (char **)calloc(3, sizeof(char *));
    if(NULL == ps_argv) {
        perror("calloc()");
        return 0;
    }
    ps_argv[0] = (char *)calloc(1, strlen("ps")+1);
    ps_argv[1] = (char *)calloc(1, strlen("aux")+1);
    strcpy(ps_argv[0], "ps");
    strcpy(ps_argv[1], "aux");
    ps_argv[2] = NULL;
    pid_t pid;
    printf("-----\n");
    pid = fork();
    if(pid == 0)
    {
        execvp("ps", ps_argv);
    }
    else if(pid > 0)
    {
        sleep(3);
    }

    return 0;

}
