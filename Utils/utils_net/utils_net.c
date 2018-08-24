/*
 * =====================================================================================
 *
 *       Filename:  utils_net.c
 *
 *    Description:  网络工具集-自用
 *
 *        Version:  1.0
 *        Created:  2018年07月19日 19时19分11秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  NYB
 *   Organization:  
 *
 * =====================================================================================
 */
#include "utils_net.h"
/*
 * return :
 *  failed: -1
 *  ok    : fd
 */
int sock_create_tcp(const char *ip, unsigned short port, int backlog)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0) {
        perror("socket()");
        return -1;
    }
    if(sock_set_reuseaddr(fd) < 0) {
        close(fd);
        return -1;
    }

    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));

    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(port);
    if(NULL == ip) {
        local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    else {
        switch(inet_pton(AF_INET, ip, &local_addr.sin_addr.s_addr)) {
        case -1:
            perror("inet_pton()");
            goto err;
        case 0:
            printf("ip is not a valid network address\n");
            goto err;
        default:
            break;
        }
    }
    if(bind(fd, (struct sockaddr *) &local_addr, sizeof(local_addr)) < 0) {
        perror("bind()");
        goto err;
    }
    if(listen(fd, backlog) < 0) {
        perror("listen()");
    }
    return fd;
err:
    close(fd);
    return -1;
}


/*
 * return :
 *  failed: -1
 *  ok    : fd
 */
int sock_connect(const char *ip, unsigned short port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0) {
        perror("socket()");
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    switch(inet_pton(AF_INET, ip, &server_addr.sin_addr.s_addr)) {
    case -1:
        perror("inet_pton()");
        goto err;
    case 0:
        printf("ip is not a valid network address\n");
        goto err;
    default:
        break;
    }

    if(connect(fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        goto err;
    }
    return fd;
err:
    close(fd);
    return -1;
}


/*
 * 连接时设置非阻塞
 * return的fd是阻塞的
 * return:
 *  failed: -1
 *  ok    : 0
 */
int sock_connect_timeout(const char *ip, unsigned short port, int timeout)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0) {
        perror("socket()");
        return -1;
    }
    
    int flags = sock_set_nonblock(fd); 
    if(flags < 0) {
        goto err;
    }
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    switch(inet_pton(AF_INET, ip, &(server_addr.sin_addr.s_addr))) {
    case -1:
        perror("inet_pton()");
        goto err;
    case 0:
        printf("ip is not a valid network address\n");
        goto err;
    default:
        break;
    }

    if(0 == connect(fd, (struct sockaddr *) &server_addr, sizeof(server_addr))) {
        if(fcntl(fd, F_SETFL, flags) < 0) {
            perror("fcntl(F_SETFL)");
            goto err;
        }
        return fd;
    }
    else {
        if(errno != EINPROGRESS) {
            perror("connect()");
            goto err;
        }
    }

    fd_set rset, wset;
    FD_ZERO(&rset);
    FD_ZERO(&wset);
    FD_SET(fd, &rset);
    FD_SET(fd, &wset);
    struct timeval tout;
    tout.tv_sec = timeout>0?timeout:0;
    tout.tv_usec = 0;
    int ret = select(fd + 1, &rset, &wset, NULL, tout.tv_sec > 0 ? &tout : NULL);
    if(ret < 0) {
        perror("select");
        goto err;
    }
    else if(0 == ret){
        printf("select() timeout\n");
        goto err;
    }
    else {
        if(FD_ISSET(fd, &rset) || FD_ISSET(fd, &wset)) {
            int error = 0;
            unsigned int len = sizeof(error);
            if(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
                perror("getsockopt");
                goto err;
            }
            else {
                if(fcntl(fd, F_SETFL, flags) < 0) {
                    perror("fcntl(F_SETFL)");
                    goto err;
                }
                return fd;
            }
        }
    }

err:
    close(fd);
    return -1;
}


/*
 * return:
 * failed : -1
 * ok     : old_flags
 */
int sock_set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if(flags < 0) {
        perror("fcntl(F_GETFL)");
        return -1;
    }
    if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("fcntl(F_SETFL)");
        return -1;
    }
    return flags;
}

/*
 * return:
 *   0  : ok
 *   -1 : failed
 */
int sock_set_reuseaddr(int _fd)
{
    int opt = 1;
    if(setsockopt(_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt(SO_REUSEADDR)");
        return -1;
    }
    return 0;
}

/*
 * return:
 *  failed: -1
 *  ok    : 0
 * get noting, if ip == NULL && port == NULL
 * only get ip: if port == NULL
 * only get port, if ip == NULL
 * get both ip and port
 */
int sock_get_peeraddr(int fd, char *ip, unsigned short *port)
{
    struct sockaddr_in sock;
    socklen_t len = sizeof(sock);
    if(getpeername(fd, (struct sockaddr *)&sock, &len) < 0) {
        return -1;
    }
    if(ip) {
        strcpy(ip, inet_ntoa(sock.sin_addr));
    }
    if(port) {
        *port = ntohs(sock.sin_port);
    }
    return 0;
}


/*
 * return:
 *  failed: -1
 *  ok    : 0
 * get noting, if ip == NULL && port == NULL
 * only get ip: if port == NULL
 * only get port, if ip == NULL
 * get both ip and port
 */
int sock_get_localaddr(int fd, char *ip, unsigned short *port)
{
    struct sockaddr_in sock;
    socklen_t len = sizeof(sock);
    if(getsockname(fd, (struct sockaddr *)&sock, &len) < 0) {
        return -1;
    }
    if(ip) {
        strcpy(ip, inet_ntoa(sock.sin_addr));
    }
    if(port) {
        *port = ntohs(sock.sin_port);
    }
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
    printf("create_udpsock_rand_port: %d\n", htons(_addr.sin_port));

    sock_get_localaddr(_fd, NULL, _port);
    return _fd;
}

int create_udpsock_rand_port_couple(const char *ip, unsigned short *_port_rtp, int *fd_rtp, int *fd_rtcp, int try)
{
    *fd_rtp = -1;
    *fd_rtcp = -1;
    while(try) {
        try--;
        printf("create_udpsock_rand_port_couple: try = %d\n", try);
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


