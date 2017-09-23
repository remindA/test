/*
 *  Name	: if_info.h
 *  Author	: ben
 *  Date	: 2017.06.09
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


extern int get_eth_MAC(char *eth_name, unsigned char *MAC);
extern int get_eth_IP(char *eth_name, unsigned char *IP);
extern int get_eth_broadaddr(char *eth_name, unsigned char *broadaddr);


#endif /* _IF_INFO_H_ */
