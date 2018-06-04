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
        for(i = 0; i < ret; i++) {
            int fd = events[i].data.fd;
            if(fd == l_fd) {
                struct sockaddr_in client_addr;
                bzero(&client_addr, sizeof(client_addr));
                socklen_t len_client = sizeof(client_addr);
                int c_fd = accept(l_fd, (struct sockaddr*)&client_addr, &len_client);
                if(c_fd < 0) {
                    perror("accept()");
                    continue;
                }
                printf("client %d on\n", c_fd);
                set_nonblock(c_fd);
                epoll_add_fd(fd_epoll, c_fd, EPOLLIN);
                printf("add client %d in events\n", c_fd);
            }
            else {
                int sd, rv;
                char buff[1024] = {0};
                while(1) {
                    rv = recv(fd, buff, sizeof(buff), 0);
                    if(rv < 0) {
                        if(errno == EINTR) {
                            continue;
                        }
                        else if(errno == EAGAIN) {
                            break;
                        }
                        else {
                            epoll_del_fd(fd_epoll, fd);
                            printf("delete %d from events\n", fd);
                            close(fd);
                            printf("close %d\n", fd);
                            break;
                        }
                    }
                    else if(rv == 0) {
                        epoll_del_fd(fd_epoll, fd);
                        printf("delete %d from events\n", fd);
                        close(fd);
                        printf("close %d\n", fd);
                    }
                    else {
                        sd = send(fd, buff, rv, 0);
                        if(sd < 0) {
                            epoll_del_fd(fd_epoll, fd);
                            printf("delete %d from events\n", fd);
                            close(fd);
                            printf("close %d\n", fd);
                        }
                    }
                }
            } 
        }
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




