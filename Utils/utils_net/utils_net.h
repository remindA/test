/*
 * =====================================================================================
 *
 *       Filename:  utils_net.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年07月21日 16时23分51秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#ifndef _UTILS_NET_H
#define _UTILS_NET_H
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>

int tcpsock_create(const char *ip, unsigned short port, int backlog);
int tcpsock_connect(const char *ip, unsigned short port);
int tcpsock_connect_timeout(const char *ip, unsigned short port, int timeout);
int sock_set_nonblock(int fd);
int sock_set_reuseaddr(int _fd);
int sock_get_peeraddr(int fd, char *ip, unsigned short *port);
int sock_get_localaddr(int fd, char *ip, unsigned short *port);

int udpsock_create(const char *_ip, unsigned short _port);
int udpsock_create_rand_port(const char *_ip, unsigned short *_port);
int udpsock_create_rand_port_couple(const char *ip, unsigned short *_port_rtp, int *fd_rtp, int *fd_rtcp, int try);


#endif

