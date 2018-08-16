/*
 * =====================================================================================
 *
 *       Filename:  read_wlock_file.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年07月31日 14时31分17秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>

int main(int argc, char **argv)
{
    if(argc != 2) {
        printf("Usage: %s file\n", argv[1]);
        return 0;
    }
    int fd = open(argv[1], O_RDONLY, 0666);
    if(fd < 0) {
        perror("open()");
        return 0;
    }
    char buff[1024] = {0};
    read(fd, buff, sizeof(buff)-1);
    close(fd);
    printf("%s\n", buff);
    return 0;
}

