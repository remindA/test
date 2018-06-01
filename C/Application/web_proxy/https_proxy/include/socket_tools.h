/*
 * =====================================================================================
 *
 *       Filename:  socket_tools.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年05月26日 10时13分34秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#ifndef _SOCKET_TOOLS_H_
#define _SOCKET_TOOLS_H_
/* ulibc: __USE_GUN
 * glibs: _GNU_SOURCE
 */
#include <math.h>
#include <fcntl.h>
#include <stdio.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include "include.h"

int readn(int fd, SSL *ssl, void *buff, int n);
int read_line(int fd, SSL *ssl, char *buff, int n);
int my_write(int fd, SSL *ssl, const char *fmt, ...);

int print_ssl_error(SSL *ssl, int ret, const char *remark);

int get_peer_addr(int fd, char *ip, unsigned short *port);
int get_local_addr(int fd, char *ip, unsigned short *port);

int create_server_socket(const char *host, unsigned short port, int max);
int connect_to_server(const char *host, unsigned short port);
int connect_to_server_nonblock(const char *host, short port, int timeout);

int is_empty_line(const char *line);
int hex2dec(const char *hex, unsigned int *dec);
#endif

