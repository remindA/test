
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char **argv)
{

}

ssize_t my_readline(int fd, void *buff, int n)
{
    int cnt = 0;
    char c;
    int ret;
    while((ret = read(fd, &c ,1)) > 0) {
        *[buff + cnt++] = c;
        if(c == '\n')
            return cnt;
    }
    return  ret;
}


int get_msqid_qnum_sr04i(int msqid)
{
    int fd = open("/proc/sysvipc/msg", O_RDONLY, 0444);
    if(fd < 0) {
        perror("open()");
    }
    char id_str[32] = {0};
    char line[256] = {0};
    int id = 0;
    int perms = 0;
    int cbytes = 0;
    int qnum = 0;
    while(my_readline(fd, line, sizeof(line)) > 0) {
        sscanf(line, "%*s %d %d %d %d %*s", &id, &perms, &cbytes, &qnum);
        printf("%d %d %d %d\n", id, perms, cbytes, qnum);
    }
    return 0;
}
