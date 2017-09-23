#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <regex.h>

#define MAX_BUFF 65535
void usage(const char *name)
{
    printf("Usage: %s src.html\n", name);
    exit(1);
}
int main(int argc, char **argv)
{
    if(argc != 2)
        usage(argv[0]);

    int fd_src = open(argv[1], O_RDONLY);
    if(fd_src < 0)
    {
        printf("open %s", argv[1]);
        perror(" ");
        exit(1);
    }

    char buff[MAX_BUFF + 1] = {0};
    int n = 0;
    while((n = read(fd_src, buff, MAX_BUFF)) > 0)
    {

    }
    close(fd_src);
    return 0;
}

int get_label_a(const char *src, char *start, char *end)
{
    char *pattern = "<>";
    regex_t *preg = NULL;
    if(regcomp(preg, pattern, ))
}
