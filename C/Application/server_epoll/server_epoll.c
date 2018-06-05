#include <time.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <assert.h>
#include <sys/epoll.h>

#include "err_quit.h"
#include "http.h"
#include "list.h"
#include "safe_free.h"
#include "include.h"
#include "socket_tools.h"

int l_fd;
int fd_epoll;
extern int h_errno;    /* for get hostbyname #include <netdb.h> */

/* system may failed somtimes, wo need to change signal behavior of SIG_CHLD */
typedef void(*sighandler_t)(int);

/* 其他 */
void usage(const char *name);
void sig_handler(int signo);
int proxy_listen(void);
void worker_thread(void *ARG);
int set_nonblock(int fd);
int epoll_add_fd(int fd_epoll, int fd, int mode);
int epoll_del_fd(int fd_epoll, int fd);
void edge_trigger(struct epoll_event *event, int ret, int epoll_fd, int l_fd);
void level_trigger(struct epoll_event *events, int ret, int epoll_fd, int l_fd);

#define MAX_EVENTS 100
int main(int argc, char **argv)
{
    openlog("server_epoll", LOG_CONS, LOG_USER);

    /* 建立socket */
    int   l_num = 500;
    char  l_host[] = "0.0.0.0";
    short l_port = HTTP_PROXY_PORT;
    l_fd = create_server_socket(l_host, l_port, l_num);
    if(l_fd < 0) {
        printf("cannot create server\n");
        syslog(LOG_INFO, "create server failed");
        return 0;
    }

    fd_epoll = epoll_create(MAX_EVENTS);
    if(fd_epoll < 0) {
        perror("epoll_create()");
        return 0;
    }
    proxy_listen();
    return 0;
}

void sig_handler(int signo)
{
    switch(signo) {
        case SIGPIPE:
            syslog(LOG_INFO, " ignore SIGPIPE");
            break;
        default:
            syslog(LOG_INFO, " exit because of sig_%d", signo);
            exit(1);
    }
}


int proxy_listen(void)
{
    printf("\n==========start proxy_listen(%d)==========\n", getpid());
    if(signal(SIGINT, sig_handler) == SIG_ERR) {
        err_quit("signal()");
    }
    printf("register SIGINT=%d\n", SIGINT);

    if(signal(SIGSEGV, sig_handler) == SIG_ERR) {
        err_quit("signal()");
    }
    printf("register SIGSEGV=%d\n", SIGSEGV);

    if(signal(SIGPIPE, sig_handler) == SIG_ERR) {
        err_quit("signal()");
    }
    printf("register SIGPIPE=%d\n", SIGPIPE);

    if(signal(SIGUSR1, sig_handler) == SIG_ERR) {
        err_quit("signal()");
    }
    printf("register SIGUSR1=%d\n", SIGUSR1);

    if(signal(SIGUSR2, sig_handler) == SIG_ERR) {
        err_quit("signal()");
    }
    printf("register SIGUSR2=%d\n", SIGUSR2);

    int i, ret;
    set_nonblock(l_fd);
    epoll_add_fd(fd_epoll, l_fd, EPOLLIN);
    struct epoll_event events[MAX_EVENTS];

    while(1) {
        ret = epoll_wait(fd_epoll, events, MAX_EVENTS, -1);
        if(ret < 0) {
            perror("epoll_wait()");
        }
        edge_trigger(events, ret, fd_epoll, l_fd);
    }
    //隐式回收
    printf("==========finish proxy_listen()==========\n");
    return 0;
}

/*
 * set fd as nonblock
 * add epoll event
 * mod epoll event
 * del epoll event
 */

int set_nonblock(int fd)
{
    int old = fcntl(fd, F_GETFL);
    int new = old | O_NONBLOCK;
    fcntl(fd, F_SETFL, new);
    return old;
}

int epoll_add_fd(int fd_epoll, int fd, int mode)
{
    struct epoll_event event;
    event.data.fd = fd;
    event.events = mode;
    epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd, &event);
}


int epoll_del_fd(int fd_epoll, int fd)
{
    epoll_ctl(fd_epoll, EPOLL_CTL_DEL, fd, NULL);
}


/*
 * 边沿触发
 * epoll事件须立即处理
 */
void edge_trigger(struct epoll_event *events, int ret, int epoll_fd, int l_fd)
{
    int i;
    for(i = 0; i < ret; i++)
    {
        int fd = events[i].data.fd;
        if(fd == l_fd) {
            struct sockaddr_in client;
            socklen_t len_client = sizeof(client);
            int c_fd = accept(l_fd, (struct sockaddr *)&client, &len_client);
            if(c_fd < 0) {
                perror("accept");
            }
            set_nonblock(c_fd);
            epoll_add_fd(epoll_fd, c_fd, EPOLLIN | EPOLLET);

            continue;
        }
        if(events[i].events & EPOLLIN) {
            printf("edge trigger once.\n");
            process_http_obj(fd);
        }
    }

}

int process_http_obj(int fd)
{
    int ret;
    int end_loop = 0;
    http_obj_t *obj = http_obj_get(fd);
    while(!end_loop) {
        switch(obj->state) {
            case _STATE_HEADER_AGAIN:
                /* switch state to recv and end loop */
                end_loop = 1;
                obj->state = _STATE_HEADER_RECV;
                break;
            case _STATE_HEADER_RECV:
                ret = read(obj->fd, obj->buff_hdr.buff+obj->tot, len-tot);
                if(ret < 0) {
                    if(errno == EINTR) {
                        continue;
                    }
                    else if(errno == EAGAIN) {
                        obj->state = _STATE_HEADER_AGAIN:
                    }
                    else {
                        perror("read()");
                        end_loop = 1;
                        obj->state = _STATE_HEADER_ERR;
                    }
                }
                else if(ret == 0) {
                    end_loop = 1;
                    printf("peer close socket\n");
                    obj->state = _STATE_HEADER_CLOSE;
                }
                else {
                    /* switch to _STATE_HEADER_PARSE */
                    obj->state = _STATE_HEADER_PARSE;
                }
                break;
            case _STATE_HEADER_PARSE:
                /* parse之后会做状态切换 */
                /*
                 * _STATE_HEADER_PARSE
                 * _STATE_HEADER_RECV
                 * _STATE_HEADER_PRCSS
                 * _STATE_HEADER_BAD
                 */
                http_parse_header(obj);
                break;
            case _STATE_HEADER_PRCSS:
                /* prcss: 进行处理,内容检测,内容替换 */
            case _STATE_HEADER_BAD:
                end_loop = 1;
                break;
            case _STATE_HEADER_ERR:
                end_loop = 1;
                break;
            case _STATE_HEADER_END:

                break;
        }

    }
}

/*
 * 调用一次只做一件事
 * 调用此函数现态一定是_STATE_HEADER_PARSE
 */
void http_parse_obj(http_obj_t *obj)
{
    int ret;
    size_t tot = obj->tot;
    size_t off = obj->off;
    size_t start = obj->off;
    const char *buff = obj->buff_hdr.buff;
    switch(locate_line(buff, tot, &off)) {
        case _LINE_HALF:
            obj->state = _STATE_HEADER_RECV; 
            break;
        case _LINE_FULL:
            if(_STATE_REQLINE == obj->line_st) {
                //解析请求行
                ret = http_parse_reqline(header, buff+start, off-start)
                    if(ret == IS_BAD_REQLINE) {
                        obj->state = _STATE_HEADER_BAD;
                    }
                obj->line_st = _STATE_FIELDLINE;
            }
            else if(_STATE_FIELDLINE == obj->line_st){
                //解析域行
                ret = http_parse_field(header, buff+start, off-start);
                if(ret == IS_BAD_FIELD) {
                    obj->state = _STATE_HEADER_BAD;
                }
                else if(ret == IS_EMPTY_LINE) {
                    /* crlf, switch to process */
                    obj->state = _STATE_HEADER_PRCSS;
                }
            }
            /* 一个完整的行，偏移量一定要改变 */
            obj->off = off;
            break;
    }
}

int http_parse_reqline(http_header_t *header, const char *buff, size_t len)
{

}

int http_parse_field(http_header_t *header, const char *buff, size_t len)
{

}


