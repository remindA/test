/*
 * =====================================================================================
 *
 *       Filename:  tcp_echo.c
 *
 *    Description:  tcp回射服务器
 *
 *        Version:  1.0
 *        Created:  2018年08月27日 17时15分08秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  NYB (), niuyabeng@126.com
 *   Organization:  
 *
 * =====================================================================================
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/select.h>
#include "utils_net.h"
#include <signal.h>

int main(int argc, char **argv)
{
    if(argc != 2) {
        printf("Usage: udp_echo port\n");
        return 0;
    }
    if(SIG_ERR == signal(SIGPIPE, SIG_IGN)) {
        perror("signal()");
    }
#define MAX_BACKLOGS 10
    int fd = sock_create_tcp("0.0.0.0", (unsigned short)atoi(argv[1]), MAX_BACKLOGS);
    if(fd < 0) {
        printf("Can not create tcp sock on 0.0.0.0:%s\n", argv[1]);
        return 0;
    }
    sock_set_nonblock(fd);
    printf("ok\n");

    struct sockaddr_in peer;
    memset(&peer, 0, sizeof(peer));
    socklen_t peer_len = sizeof(peer);
    int fd_max = -1; 
    fd_set rset;
    FD_ZERO(&rset);
    struct timeval tv;
    int i;
    int ret;
    int c_fd[MAX_BACKLOGS] = {0};
    while(1) {
        fd_max = -1;
        tv.tv_sec = 3;
        tv.tv_usec = 0;
        FD_SET(fd, &rset);
        fd_max = fd_max<fd?fd:fd_max;
        for(i = 0; i < MAX_BACKLOGS; i++) {
            if(c_fd[i] > 0) {
                FD_SET(c_fd[i], &rset);
                fd_max = fd_max<c_fd[i]?c_fd[i]:fd_max;
            }
        }
        //printf("fd_max = %d\n", fd_max);
        ret = select(fd_max+1, &rset, NULL, NULL, &tv);
        if(ret < 0) {
            perror("select()");
            break;
        }
        else if(ret == 0) {
            //printf("select timeout!\n");
        }
        else {
            if(FD_ISSET(fd, &rset)) {
                for(i = 0; i< MAX_BACKLOGS; i++) {
                    if(c_fd[i] <= 0) {
                        c_fd[i] = accept(fd, (struct sockaddr *)&peer, &peer_len);
                        if(c_fd[i] < 0) {
                            perror("accept()");
                        }
                        printf("client on, fd = %d\n", c_fd[i]);
                        break;
                    }
                }
            }
            for(i = 0; i < MAX_BACKLOGS; i++) {
                if(c_fd[i] > 0 && FD_ISSET(c_fd[i], &rset)) {
                    char buff[700000] = {0};
                    ret = read(c_fd[i], buff, sizeof(buff));
                    if(ret <= 0) {
                        perror("read()");
                        close(c_fd[i]);
                        c_fd[i] = 0;
                        continue;
                    }   
                    printf(" read: %.*s\n", ret, buff);
                    //printf(" read: %d bytes\n", ret);
                    ret = write(c_fd[i], buff, ret);
                    if(ret <= 0) {
                        close(c_fd[i]);
                        c_fd[i] = 0;
                        continue;
                    }
                    printf("write: %.*s\n", ret, buff);
                    //printf(" write: %d bytes\n", ret);
                }
            }
        }
    }
    return 0;
}

