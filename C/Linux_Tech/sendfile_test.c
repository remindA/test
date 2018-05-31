/*
 * =====================================================================================
 *
 *       Filename:  sendfil_test.c
 *
 *    Description:  测试sendfile
 *
 *        Version:  1.0
 *        Created:  2018年05月31日 23时01分32秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sendfile.h>

/*
 * 文件拷贝
 */
void usage(const char *name)
{
    printf("%s src dst ...\n", name);
}

int main(int argc, char **argv)
{
    if(argc <= 2) {
        usage(argv[0]);
        return 0;
    }
    int i;
    int ret;
    int fd_src;
    int fd_dst;
    char *dst;
    char *src;
    struct stat st;
    src = argv[1];
    fd_src = open(src, O_RDONLY, 0444);
    if(fd_src < 0) {
        perror("open");
        return -1;
    }
    fstat(fd_src, &st);
    for(i = 2, dst = argv[i]; i < argc; i++, dst = argv[i]) {
        fd_dst = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if(fd_dst < 0) {
            perror("open");
            continue;
        }
        /*make offset = 0 */
        lseek(fd_src, 0, SEEK_SET);
        ret = sendfile(fd_dst, fd_src, NULL, st.st_size);
        if(ret < 0) {
            perror("sendfile");
        }
        close(fd_dst);
    }

    return 0;
}
