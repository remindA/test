/*
 * =====================================================================================
 *
 *       Filename:  udp_echo_server.c
 *
 *    Description:  udp回射服务器测试客户端
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
#include "utils_net.h"

int main(int argc, char **argv)
{
    if(argc != 3) {
        printf("Usage: udp_echo ip port\n");
        return 0;
    }

    unsigned short port;
    int fd = create_udpsock_rand_port("0.0.0.0", &port);
    if(fd < 0) {
        printf("Can not create udp sock\n");
        return 0;
    }
    struct sockaddr_in peer;
    memset(&peer, 0, sizeof(peer));
    peer.sin_family = AF_INET;
    peer.sin_port = htons(atoi(argv[2]));
    peer.sin_addr.s_addr = inet_addr(argv[1]);
    socklen_t peer_len = sizeof(peer);

    fd_set rset;
    FD_ZERO(&rset);
    int ret;
    char *content = "This is a udp test program.\n";
    while(1) {
        char buff[65535] = {0};
        sendto(fd, content, strlen(content), 0, (struct sockaddr *)&peer, peer_len);
        ret = recvfrom(fd, buff, sizeof(buff)-1, 0, (struct sockaddr *)&peer, &peer_len);
        if(ret < 0) {
            perror("recvfrom()");
        }
        else {
            printf("%s", buff);
        }
        sleep(1);
    }
    return 0;
}

