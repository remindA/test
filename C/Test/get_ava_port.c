/*
 * =====================================================================================
 *
 *       Filename:  get_ava_port.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年06月27日 12时29分04秒
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
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

int get_local_addr(int fd, char *ip, unsigned short *port);
int create_udpsock(const char *_ip, unsigned short _port);
int create_udpsock_rand_port(const char *_ip, unsigned short *_port);
int create_udpsock_couple(const char *ip, unsigned short *_port_rtp, int *fd_rtp, int *fd_rtcp, int try);

int get_local_addr(int fd, char *ip, unsigned short *port)
{
    struct sockaddr_in sock;
    socklen_t len = sizeof(sock);
    getsockname(fd, (struct sockaddr *)&sock, &len);
    if(ip) {
        strcpy(ip, inet_ntoa(sock.sin_addr));
    }
    if(port) {
        *port = ntohs(sock.sin_port);
    }
    return 0;
}

int create_udpsock_couple(const char *ip, unsigned short *_port_rtp, int *fd_rtp, int *fd_rtcp, int try)
{
    *fd_rtp = -1;
    *fd_rtcp = -1;
    while(try) {
        try--;
        printf("try = %d\n", try);
        *fd_rtp = create_udpsock_rand_port(ip, _port_rtp);
        if(*fd_rtp < 0) {
            printf("create_udpsock_couple: create random\n");
            continue;
        }
        if(*_port_rtp %2) {
            close(*fd_rtp);
            printf("create_udpsock_couple: port =%d, is not even\n", *_port_rtp);
            continue;
        }
        *fd_rtcp = create_udpsock(ip, (*_port_rtp) + 1);
        if(*fd_rtcp < 0) {
            close(*fd_rtp);
            printf("create_udpsock_couple: Can not crate in port odd %d\n", *_port_rtp + 1);
            continue;
        }
        else {
            break;
        }
    }
    if((*_port_rtp %2 == 0) && (fd_rtp > 0) && (fd_rtcp > 0)) {
        return 0;
    }
    return -1;
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
    inet_pton(AF_INET, _ip, &_addr.sin_addr.s_addr);
    if(bind(_fd, (struct sockaddr *) &_addr, sizeof(_addr)) < 0) {
        perror("create_tcpsock: bind()");
        return -1;
    }
    
    return _fd;
}

int create_udpsock_rand_port(const char *_ip, unsigned short *_port)
{
    int _fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(_fd < 0) {
        perror("create_udpsock: socket()");
        return -1;
    }
    struct sockaddr_in _addr;
    memset(&_addr, 0, sizeof(_addr));
    _addr.sin_family = AF_INET;
    _addr.sin_port = htons(0);
    if(NULL == _ip) {
        _addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } 
    inet_pton(AF_INET, _ip, &_addr.sin_addr.s_addr);
    if(bind(_fd, (struct sockaddr *) &_addr, sizeof(_addr)) < 0) {
        perror("create_tcpsock: bind()");
        return -1;
    }
    
    get_local_addr(_fd, NULL, _port);
    return _fd;
}


int main(int argc, char **argv)
{
    int rtp = -1;
    int rtcp = -1;
    unsigned short port = 0;
    create_udpsock_couple("10.10.10.109", &port, &rtp, &rtcp, 1);
    if(rtp > 0) {
        printf("port = %d, rtp = %d, rtcp = %d\n", port, rtp, rtcp);
    }
    while(1) {
        sleep(10000);
    }
    return 0;
}

