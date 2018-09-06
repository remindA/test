/*
 * =====================================================================================
 *
 *       Filename:  udp_echo_server.c
 *
 *    Description:  udp回射服务器
 *
 *        Version:  1.0
 *        Created:  2018年08月22日 17时15分08秒
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

int main(int argc, char **argv)
{
    if(argc != 2) {
        printf("Usage: udp_echo port\n");
        return 0;
    }
    int fd = create_udpsock("0.0.0.0", (unsigned short)atoi(argv[1]));
    if(fd < 0) {
        printf("Can not create udp sock on 0.0.0.0:%s\n", argv[1]);
        return 0;
    }
    sock_set_nonblock(fd);

    struct sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);
    fd_set rset;
    FD_ZERO(&rset);
    int ret;
    while(1) {
        FD_SET(fd, &rset);
        ret = select(fd+1, &rset, NULL, NULL, NULL);
        if(ret < 0) {
            perror("select()");
            continue;
        }
        else if(ret == 0) {
            printf("select timeout\n");
            continue;
        }
        else {
            char buff[65535] = {0};
            ret = recvfrom(fd, buff, sizeof(buff)-1, 0, (struct sockaddr *)&peer, &peer_len);
            if(ret < 0) {
                perror("recvfrom()");
            }
            else {
                printf("len = %d, buff = [%s]\n", ret, buff);
                sendto(fd, buff, ret, 0, (struct sockaddr *)&peer, peer_len);
            }
        }
    }
    return 0;
}

