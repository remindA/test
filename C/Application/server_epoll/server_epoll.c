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
struct list_head obj_tab;
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
int http_recv_handler(http_obj_t *obj); 
int process_http_header(http_obj_t *obj);
int http_header_parseline(http_header_t *header);
int http_send_handler(http_obj_t *obj);

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
            printf("ignore SIGPIPE\n");
            syslog(LOG_INFO, " ignore SIGPIPE");
            break;
        default:
            printf("exit cause of sig_%d\n", signo);
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

    int ret;
    set_nonblock(l_fd);
    epoll_add_fd(fd_epoll, l_fd, EPOLLIN);
    struct epoll_event events[MAX_EVENTS];
    init_list_head(&obj_tab);

    /* 可创建线程做额外的工作 */
    while(1) {
        ret = epoll_wait(fd_epoll, events, MAX_EVENTS, -1);
        if(ret < 0) {
            perror("epoll_wait()");
            continue;
        }
        edge_trigger(events, ret, fd_epoll, l_fd);
    }
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
    int rt;
    for(i = 0; i < ret; i++)
    {
        int fd = events[i].data.fd;
        if(fd == l_fd) {
            printf("listen edge trigger once.\n");
            struct sockaddr_in client;
            socklen_t len_client = sizeof(client);
            int c_fd = accept(l_fd, (struct sockaddr *)&client, &len_client);
            if(c_fd < 0) {
                perror("accept");
            }
            http_obj_t *obj = http_obj_create();
            if(obj && (http_obj_init(obj, c_fd) > 0)) {
                set_nonblock(c_fd);
                epoll_add_fd(epoll_fd, c_fd, EPOLLIN | EPOLLET);
                list_add_tail(&(obj->list), &obj_tab);
            }
            else {
                close(c_fd);
            }
            printf("finish listen edge trigger\n");
            continue;
        }

        printf("client edge trigger once.\n");
        http_obj_t *obj = http_obj_get(&obj_tab, fd);
        if(NULL == obj) {
            printf("can not happen, and it happend\n");
            continue;
        }
        if(events[i].events & EPOLLIN) {
            rt = http_recv_handler(obj);
            switch(rt) {
                case _OBJ_AGN:
                    break;
                case _OBJ_ERR:
                case _OBJ_CLS:
                case _OBJ_BAD:
                    list_del(&(obj->list));
                    http_obj_free(obj);
                    SAFE_FREE(obj);
                    epoll_del_fd(epoll_fd, fd);
                    close(fd);
                    break;
            }
        }
        if(events[i].events &EPOLLOUT) {
            rt = http_send_handler(obj);
            switch(rt) {
                case _OBJ_AGN:
                    break;
                case _OBJ_ERR:
                    list_del(&(obj->list));
                    http_obj_free(obj);
                    SAFE_FREE(obj);
                    epoll_del_fd(epoll_fd, fd);
                    close(fd);
                    break;
            }
        }
    }

}


/*
 * obj状态
 *      header
 *      body
 *      error
 *      close
 *      bad
 */
int http_recv_handler(http_obj_t *obj) 
{
    /*
     * 根据obj->state来走流程
     */
    int ret;
    while(1) {
        switch(obj->state) {
            case STATE_OBJ_HDR:
                printf("STATE_OBJ_HDR\n");
                ret = process_http_header(obj);
                if(ret == _HEADER_ERR) {
                    obj->state = STATE_OBJ_ERR;
                }
                else if(ret == _HEADER_CLS) {
                    obj->state = STATE_OBJ_CLS;
                }
                else if(ret == _HEADER_AGN) {
                    obj->state = STATE_OBJ_HDR;  /* not necessary */
                    return _OBJ_AGN;
                }
                else if(ret == _HEADER_CON){
                    obj->state = STATE_OBJ_HDR; /* not necessary */
                }
                else if(ret == _HEADER_END) {
                    obj->state = STATE_OBJ_BDY;
                }
                break;
            case STATE_OBJ_BDY:
                {
                    /* 支持请求的content-length, chunked, gzip*/
                    ret = process_http_body(obj);
                     
                }

                /* err, close, bad都意味着本次请求将会被终止 */
            case STATE_OBJ_ERR:
                printf("STATE_OBJ_ERR\n");
                return _OBJ_ERR;
            case STATE_OBJ_CLS:
                printf("STATE_OBJ_CLS\n");
                return _OBJ_CLS;
            case STATE_OBJ_BAD:
                printf("STATE_OBJ_BAD\n");
                return _OBJ_BAD;
        }
    }
}


/*
 * 此函数只用于读取并解析reqhdr
 * reqhdr状态
 *      recv
 *      parse
 */
int process_http_header(http_obj_t *obj)
{
    int fd = obj->fd;
    http_header_t *reqhdr = &(obj->reqhdr);
    int ret;
    switch(reqhdr->state) {
        case STATE_HEADER_RECV: 
            printf("STATE_HEADER_RECV\n");
            ret = readline_nonblock(fd, &(reqhdr->line));
            if(ret == _READLINE_ERR) {
                reqhdr->state = STATE_HEADER_RECV; /* not necessary */ 
                return _HEADER_ERR;
            }
            else if(ret == _READLINE_CLS) {
                reqhdr->state = STATE_HEADER_RECV; /* not necessary */ 
                return _HEADER_CLS;
            }
            else if(ret == _READLINE_AGN) {
                reqhdr->state = STATE_HEADER_RECV; /* not necessary */ 
                return _HEADER_AGN;
            }
            /* full line */ 
            else if(ret == _READLINE_END){
                reqhdr->state = STATE_HEADER_PARSE; 
                return _HEADER_CON;
            }
            break;
        case STATE_HEADER_PARSE:
            printf("STATE_HEADER_PARSE\n");
            ret = http_header_parseline(reqhdr);
            if((ret == _PARSELINE_BAD_FIRST) || (ret == _PARSELINE_BAD_FIELD)) {
                printf("_parseline_bad\n");
                reqhdr->state = STATE_HEADER_RECV;  /* not necessary */
                return _HEADER_BAD;
            }
            else if(ret == _PARSELINE_CON) {
                printf("_parseline_con\n");
                reqhdr->state = STATE_HEADER_RECV;
                return _HEADER_CON;
            }
            else if(ret == _PARSELINE_ERR) {
                printf("_parseline_err\n");
                reqhdr->state = STATE_HEADER_RECV;  /* not necessary */
                return _HEADER_ERR;
            }
            else if(ret == _PARSELINE_EPT){
                printf("_parseline_ept\n");
                redhdr->state = STATE_HEADER_END;
                return __HEADER_MAX;
            }
            break;
        case STATE_HEADER_END:
            printf("STATE_HEADER_END\n");
            return _HEADER_END;
    }
}

int http_header_parseline(http_header_t *header)
{
    int ret;
    switch(header->state_line) {
        case STATE_LINE_FIRST:
            printf("STATE_LINE_FIRST\n");
            header->state_line = STATE_LINE_FIELD;
            ret = http_parse_firstline(header);
            line_reset(&(header->line));
            return ret;
        case STATE_LINE_FIELD:
            printf("STATE_LINE_FIELD\n");
            header->state_line = STATE_LINE_FIELD; /* not necessary */
            ret = http_parse_field(header);
            line_reset(&(header->line));
            return ret;
    }
}




