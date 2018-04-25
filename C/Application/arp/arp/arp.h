#ifndef  _MY_ARP_H
#define _MY_ARP_H
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <string.h>


extern int arpDel(char *ifname, char *ipStr);
extern int arpGet(char *ifname, char *ipStr);
extern int getHwAddr(char *buff, char *mac);
extern int arpSet(char *ifname, char *ipStr, char *mac);

#endif

