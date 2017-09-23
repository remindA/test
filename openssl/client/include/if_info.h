/*
 * if_info.h
 *
 *  Created on: 2017年6月9日
 *      Author: ben
 */

#ifndef _IF_INFO_H_
#define _IF_INFO_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

/* arp使用原始套接字编程时使用
 * unsigned char ip[4]
 * unsigned char mac[6]
 */

//mac地址按照十进制存放在MAC[6]数组中
extern int get_eth_MAC(char *eth_name, unsigned char *MAC);

//ip地址按照十进制格式存放在IP[4]数组中
extern int get_eth_IP(char *eth_name, unsigned char *IP);

//广播地址以十进制格式存放在broadaddr[4]数组中
extern int get_eth_broadaddr(char *eth_name, unsigned char *broadaddr);


#endif
