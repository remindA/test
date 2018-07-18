/*
 * =====================================================================================
 *
 *       Filename:  socketpair_test.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年07月05日 21时55分28秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <pwd.h>
#include <pthread.h>
#include <sys/time.h>


int create_udpsock(const char *_ip, unsigned short _port);

int main(int argc, char **argv)
{
    if(argc != 3) {
        printf("Usage: %s ip port\n", argv[0]);
    }
    int s_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(s_fd < 0) {
        perror("socket()");
        return 0;
    }

    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    addr.sin_family = AF_INET;
    inet_aton(argv[1], &(addr.sin_addr));
    addr.sin_port = htons(atoi(argv[2]));
    if(connect(s_fd, (struct sockaddr *)&addr, len) < 0) {
        perror("connect()");
        return 0;
    }
    if(send(s_fd, "port", 4, 0) < 0) {
        perror("send()");
        printf("errno = %d\n", errno);
    }
    char buff[1024] = {0};
    if(recv(s_fd, buff, 1024, 0) < 0) {
        perror("recv()");
    }

    printf("%s:%s\n", argv[1], argv[2]);
    return 0;
}

int create_udpsock(const char *_ip, unsigned short _port)
{
    int _fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(_fd < 0) {
        perror("create_udpsock: socket()");
        return -1;
    }
    struct sockaddr_in _addr;
    memset(&_addr, 0, sizeof(_addr));
    _addr.sin_family = AF_INET;
    _addr.sin_port = htons(_port);
    if(NULL == _ip) {
        _addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } 
    else {
        inet_pton(AF_INET, _ip, &_addr.sin_addr.s_addr);
    }
    if(bind(_fd, (struct sockaddr *) &_addr, sizeof(_addr)) < 0) {
        perror("create_tcpsock: bind()");
        return -1;
    }

    return _fd;
}
