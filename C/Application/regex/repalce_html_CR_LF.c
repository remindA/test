#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define MAX_BUFF 65535
void usage(const char *name)
{
    printf("Usage: %s src.html dst.html\n", name);
    exit(1);
}
int main(int argc, char **argv)
{
    if(argc != 3)
        usage(argv[0]);

    int fd_src = open(argv[1], O_RDONLY);
    int fd_dst = open(argv[2], O_CREAT | O_TRUNC | O_WRONLY);
    if(fd_src < 0)
    {
        printf("open %s", argv[1]);
        perror(" ");
        exit(1);
    }
    if(fd_dst < 0)
    {
        printf("open %s", argv[2]);
        perror(" ");
        exit(1);
    }

    char buff[MAX_BUFF + 1] = {0};
    int n = 0;
    while((n = read(fd_src, buff, MAX_BUFF)) > 0)
    {
        int i = 0;
        for(i = 0; i < n; i++)
            buff[i] = (buff[i] == '\r' || buff[i] == '\n')?(char)0x20:buff[i];
        if(write(fd_dst, buff, n) < 0)
            perror("write");
    }
    close(fd_src);
    close(fd_dst);
    return 0;

}
