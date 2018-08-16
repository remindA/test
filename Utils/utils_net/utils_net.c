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


