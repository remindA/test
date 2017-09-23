#include <unistd.h>
#include <stdio.h>

int main()
{
    int pid = -1;

    pid = fork();
    switch(pid)
    {
        case 0:
            printf("child\n");
            break;
        case -1:
            perror("fork");
            break;
        default:
            printf("father\n");
    }
    return 0;

}
