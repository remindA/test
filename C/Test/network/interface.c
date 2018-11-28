/*
 * =====================================================================================
 *
 *       Filename:  interface.c
 *
 *    Description:  get interface infos
 *
 *        Version:  1.0
 *        Created:  2018年11月29日 00时22分00秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

/*
 * ioctl()获取网卡的所有信息
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>

/*
 * 如果缓冲区不够怎么办?
 *      只会取出部分的网卡信息
 */

int get_all_interface_name()
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0) {
        perror("socket()");
        return -1;
    }
    struct ifconf _ifconf;
    struct ifreq  _ifreq[1];
    _ifconf.ifc_len = 1 * sizeof(struct ifreq);
    _ifconf.ifc_buf = (char *)_ifreq;

    if(ioctl(fd, SIOCGIFCONF, (char *)&_ifconf) < 0) {
        perror("ioctl(SIOCGIFCONF)");
        close(fd);
        return -1;
    }
    int i;
    int len = _ifconf.ifc_len/sizeof(struct ifreq);
    for(i = 0; i < len; i++) {
        printf("Interface: %s\n", _ifreq[i].ifr_name);
    }
    printf("\n");
    return 0;
}

int main()
{
    return get_all_interface_name();
}



