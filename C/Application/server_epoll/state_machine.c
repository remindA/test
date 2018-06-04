#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>



#define BUFFER_SIZE 4096

enum CHECK_STATE {
    CHECK_STATE_REQUESTLINE = 0,
    CHECK_STATE_HEADER
};

enum LINE_STATUS {
    LINE_OK = 0,
    LINE_BAD,
    LINE_WAIT
};

enum HTTP_CODE {
    NO_REQUEST,
    GET_REQUEST,
    BAD_REQUEST,
    FORBIDDEN_REQUEST,
    INTERNAL_ERROR,
    CLOSED_CONNECTION
};

static const char *szret[] = {
    "i get correct result\n",
    "something wrong\n"
};

/*
 *
 * 函数调用期间*off和*tot都可能会改变
 * off: 
 *      传入: 本行起始下标
 *      传出: 下一行起始下标
 * tot  : buffer总长度
 */
int locate_line(const char *buffer, int tot, int *off)
{
    while(*off < tot) {
        if('\n' == buffer[*off]) {
            *off++;
            return LINE_OK;
        }
        *off++;
    }
    return LINE_WAIT;
}


int parse_header(const char *buffer, int tot, int *off, int *state)
{
    int ret;
    int line_st;
    while(1) {
        int start = *off;
        line_st = locate_line(buffer, off, tot);
        if(line_st != LINE_OK) {
            break;
        }
        switch(*state) {
            case LINE_PARSE_CONTINUE:
                parse_line(buffer+start, *off-start, state);
            case LINE_PARSE_BREAK:
                return HEADER_OK;
            case LINE_PARSE_ERR:
                return HEADER_ERR;
        }
    }
    if(line_st == LINE_WAIT) {
        return NO_REQUEST;
    }

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


void worker(int c_fd)
{
    int  rd  = 0;
    int  tot = 0;
    int  off = 0;
    char buffer[4096] = {0};
    while(1) {
        rd = recv(c_fd, buffer+tot, sizeof(buffer)-tot);
        if(rd < 0) {
            if(errno == EINTR) {
                continue;
            }
            else {
                close(c_fd);
                break;
            }
        }
        else if(rd == 0) {
            close(c_fd);
            break;
        }
        tot += rd;
        HTTP_CODE result = parse_header(buffer, &off, tot);
        if(result == NO_REQUEST) {
            continue;
        }
        else if(result == GET_REQUEST) {
            send(c_fd, buffer, tot, 0);
            break;
        }
        else {
            char *err = "Something wrong\n";
            send(c_fd, err, strlen(err), 0);
            break;
        }
    }
}


int main(int argc, char **argv)
{
    int  num = 500;
    char host[] = "0.0.0.0";
    unsigned short port = 8080;
    int l_fd = create_server_socket(host, port, num);
    if(l_fd < 0) {
        printf("create_server: failed\n");
        exit(0);
    }
    while(1) {
        struct sockaddr_in client;
        socklen_t len_client = sizeof(client);
        int c_fd = accept(l_fd, (struct sockaddr *)&client, &len_client);
        if(c_fd < 0) {
            perror("accept()");
            continue;
        }
        worker(c_fd);
    }
}


















