/*
 * =====================================================================================
 *
 *       Filename:  socket_tools.c
 *
 *    Description:  
 *                  1. 创建服务套接字
 *                  2. 创建客户套接字
 *                  3. 读写封装
 *     
 *        Version:  1.0
 *        Created:  2018年05月26日 09时58分29秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#include "socket_tools.h"

int get_peer_addr(int fd, char *ip, unsigned short *port)
{
    struct sockaddr_in sock;
    socklen_t len = sizeof(sock);
    getpeername(fd, (struct sockaddr *)&sock, &len);
    strcpy(ip, inet_ntoa(sock.sin_addr));
    *port = ntohs(sock.sin_port);
    return 0;
}

int get_local_addr(int fd, char *ip, unsigned short *port)
{
    struct sockaddr_in sock;
    socklen_t len = sizeof(sock);
    getsockname(fd, (struct sockaddr *)&sock, &len);
    strcpy(ip, inet_ntoa(sock.sin_addr));
    *port = ntohs(sock.sin_port);
    return 0;
}


int create_server_socket(const char *host, unsigned short port, int max)
{
#ifdef FUNC
    printf("==========start create_proxy_server()==========\n");
#endif
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0) {
        return -1;
    }
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));

    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(port);
    if(NULL == host) {
        local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } 
    inet_pton(AF_INET, host, &local_addr.sin_addr.s_addr);
    if(bind(fd, (struct sockaddr *) &local_addr, sizeof(local_addr)) < 0) {
        return -1;
    }
    if(listen(fd, max) < 0) {
        return -1;
    }
#ifdef FUNC
    printf("==========finish create_proxyy_server()==========\n");
#endif
    return fd;
}

int connect_to_server(const char *host, unsigned short port)
{
#ifdef FUNC
    printf("==========start create_real_server()==========\n");
#endif
#ifdef DEBUG
    printf("create_real_server host=%s, port=%d\n", host, port);
#endif
    int s_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(s_fd < 0) {
        perror("socket()");
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    struct hostent *server;
    if((server = gethostbyname(host)) == NULL)
    {
        printf("\033[31m");
        printf("gethostbyname [%s] error, h_error=%d, %s\n", host, h_errno, hstrerror(h_errno));
        printf("\033[0m");
        close(s_fd);
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    memcpy(&(server_addr.sin_addr.s_addr), server->h_addr, server->h_length);

    if(connect(s_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        return -1;
    }
#ifdef DEBUG
    printf("connected to %s:%d\n", host, port);
#endif
#ifdef FUNC
    printf("==========finish create_real_server()==========\n");
#endif
    return s_fd;
}

int connect_to_server_nonblock(const char *host, short port, int timeout)
{
    /* 建立和服务器的连接 */
#ifdef FUNC
    printf("==========start create_real_server_nonblock()==========\n");
#endif
    int s_fd = socket(AF_INET, SOCK_STREAM, 0);

    if(s_fd < 0) {
        perror("socket()");
        return -1;
    }
    /* 设置非阻塞 */
    int flags = fcntl(s_fd, F_GETFL, 0);
    if(flags < 0)
    {
        perror("fcntl f_get");
        goto end;
    }
    if(fcntl(s_fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        perror("fcntl f_set");
        goto end;
    }

    struct sockaddr_in server_addr;
    struct hostent *server;
    if((server = gethostbyname(host)) == NULL)
    {
        printf("\033[31m");
        printf("gethostbyname [%s] error, h_error=%d, %s\n", host, h_errno, hstrerror(h_errno));
        printf("\033[0m");
        goto end;
    }
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    /* inet_pton(AF_INET, host, &(server_addr.sin_addr.s_addr)); */
    memcpy(&(server_addr.sin_addr.s_addr), server->h_addr, server->h_length);
    //#ifdef DEBUG
    char ip[16] = {0};
    printf("%s <--> %s port=%d\n", host, inet_ntop(AF_INET, server->h_addr, ip, sizeof(ip)), port);
    //#endif
    if(connect(s_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0)
    {
        if(errno != EINPROGRESS)
        {
            //#ifdef DEBUG
            syslog(LOG_INFO, "cannot connect to %s:%d", inet_ntop(AF_INET, server->h_addr, ip, sizeof(ip)), port);
            printf("connect err\n");
            //#endif
            goto end;
        }
    }
    fd_set rset, wset;
    FD_ZERO(&rset);
    FD_ZERO(&wset);
    FD_SET(s_fd, &rset);
    FD_SET(s_fd, &wset);
    struct timeval tout;
    tout.tv_sec = timeout>0?timeout:0;
    tout.tv_usec = 0;
    int ret = select(s_fd + 1, &rset, &wset, NULL, tout.tv_sec > 0 ? &tout : NULL);
    if(ret > 0)
    {
        if(FD_ISSET(s_fd, &rset) || FD_ISSET(s_fd, &wset))
        {
            int error = 0;
            unsigned int len = sizeof(error);
            if(getsockopt(s_fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
            {
                perror("getsockopt");
                goto end;
            }
            else
            {
                /* 改回非阻塞 */
                if(fcntl(s_fd, F_SETFL, flags) < 0)
                    goto end;
                return s_fd;
            }
        }
    }
    else if(ret == 0)
    {
#ifdef DEBUG
        printf("select timeout!\n");
#endif
        goto end;
    }
    else
    {
        perror("select");
        goto end;
    }

end:
    close(s_fd);
#ifdef FUNC
    printf("==========finish create_real_server_nonblock()==========\n");
#endif
    return -1;
}

int is_empty_line(const char *line, int len)
{
    if(NULL == line) {
        return 0;
    }

    if(len > 2 || len == 0) {
        return 0;
    }
    else {
        return len==1?(line[0]=='\n'):((line[0]=='\r')&&(line[1]=='\n'));
    }
}

int hex2dec(const char *hex, unsigned int *dec)
{
#ifdef FUNC
    printf("==========start hex2dec()==========\n");
#endif
    int i = 0;
    int power;
    int max_power = strlen(hex);
    *dec = 0;
    for(i = 0; i < max_power; i++)
    {
        int truth;
#ifdef DEBUG_HTTP
        printf("hex[%d]=%c\n", i, hex[i]);
#endif
        if(hex[i] >= '0' && hex[i] <= '9')
            truth = hex[i] - '0';
        else if(hex[i] >= 'a' && hex[i] <= 'f')
            truth = hex[i] - 'a' + 10;
        else if(hex[i] >= 'A' && hex[i] <= 'F')
            truth = hex[i] - 'A' + 10;
        else
            return -1;
        power = max_power - i - 1;
#ifdef DEBUG_HTTP
        printf("truth=%d, power=%d\n", truth, power);
#endif
        *dec += (unsigned int)(truth * pow(16, power));
    }
#ifdef FUNC
    printf("==========finish hex2dec()==========\n");
#endif
    return 0;
}

/*********************************
 
  非阻塞io接口封装

 **********************************/

int line_calloc(line_t *line, size_t max)
{
    line->buff = (char *)calloc(1, max);
    if(NULL == line->buff) {
        perror("calloc()");
        return -1;
    }
    line->max = max;
    line_reset(line);
    return 1;
}

int line_realloc(line_t *line, size_t step)
{
    line->buff = (char *)realloc(line->buff, line->max+step);
    if(NULL == line->buff) {
        return -1;
    }
    line->max += step;
    return 1;
}

void line_reset(line_t *line)
{
    memset(line->buff, 0, line->max);
    line->tot = 0;
    line->state = LINE_HALF;
}

int readline_nonblock(int fd, line_t *line)
{
#ifdef FUNC
    printf("==========start _read_line_nonblock()==========\n");
#endif
    int n = 0;
    char c = 0;

    while (LINE_HALF == line->state) {
        n = read(fd, &c, 1);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            else if(errno == EAGAIN) {
                return _READLINE_AGN;
            }
            else {
                return _READLINE_ERR;
            }
        }
        else if (n == 0) {
            return _READLINE_CLS;
        }
        else {
            if(line->tot < (line->max-1)) {
                line->buff[line->tot] = c;
                line->tot += 1;
            }
            else {
                /* 扩容 */
                line->buff = realloc(line->buff, line->max+LINE_EXT_STEP);
                if(NULL == line->buff) {
                    perror("realloc()");
                    line->max = 0;
                    line->tot = 0;
                    return _READLINE_ERR;
                }
                line->max += LINE_EXT_STEP;
                line->buff[line->tot] = c;
                line->tot += 1;
            }
        }
        if (c == '\n')
            line->state = LINE_FULL;
    }
#ifdef FUNC
    printf("==========finish _read_line()==========\n");
#endif
    printf("line = [%s]\n", line->buff);
    return _READLINE_END;
}

/*
关于line解析
    switch(line->state) {
        case LINE_HALF:
            ret = readline_nonblock(fd, line);
            break;
        case LINE_FULL:
            break;
        }
    }
    if(ret == READLINE_ERR || ret == READLINE_CLS) {
        return ret;
    }
    
 */



/*
 * return: 
 *  -1:  ERR
 *   0:  CLS
 *   1:  AGN
 *   2:  END
 */
int readn_nonblock(int fd, buffer_t *buffer)
{
#ifdef FUNC
    printf("==========start _readn()==========\n");
#endif
    int n;
    while (buffer->tot < buffer->max) {
        n = read(fd, buffer->buff+buffer->tot, buffer->max-buffer->tot);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            else if(errno == EAGAIN)
            {
                return _READN_AGN;
            }
            else {
                return _READN_ERR;
            }
        }
        else if (n == 0) {
            return _READN_CLS;
        }
        buffer->tot += n;
    }
#ifdef FUNC
    printf("==========finish _readn()==========\n");
#endif
    return _READN_END;
}
