/*
 * =====================================================================================
 *
 *       Filename:  lock_file_test.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年07月31日 13时52分49秒
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
    if(argc != 3) {
        printf("Usage: %s file string\n", argv[0]);
        return 0;
    }
    int fd = open(argv[1], O_WRONLY, 0666);
    if(fd < 0) {
        perror("open()");
        return 0;
    }
    struct flock lock;
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;
    if(fcntl(fd, F_SETLKW, &lock) != 0) {
        perror("fcntl()");
        close(fd);
        return 0;
    }
    printf("lock %s ok\n", argv[1]);
    ftruncate(fd, 0);
    lseek(fd, 0, SEEK_SET);
    write(fd, argv[2], strlen(argv[2]));
    if(fsync(fd) < 0) {
        perror("fsync()");
    }
    sleep(30);
    lock.l_type = F_UNLCK;
    fcntl(fd, F_SETLKW, &lock);
    printf("unlockpt %s ok\n", argv[1]);
    close(fd);
    return 0;
}


