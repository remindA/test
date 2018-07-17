/*
 * =====================================================================================
 *
 *       Filename:  utils_net.h
 *
 *    Description:  as file name
 *
 *        Version:  1.0
 *        Created:  2018年06月22日 10时00分58秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  NYB 
 *   Organization:  
 *
 * =====================================================================================
 */
#ifndef _UTILS_NET_H_
#define _UTILS_NET_H_

/*
 * 为防止全局变量的名称和局部变量相同
 * 接口函数内定义的变量start with '_'
 */

int create_tcpsock(const char *ip, unsigned short port, int backlog);
int create_tcpsock_nonblock(const char *ip, unsigned short port, int backlog);

int create_udpsock(const char *ip, unsigned short port);
int create_udpsock_nonblock(const char *ip, unsigned short port);

int sock_set_nonblock(int _fd);
int sock_set_reuseraddr(int _fd);

/* 获取网卡信息 */
int get_eth_ip(const char *ethname, char *ip);
int get_eth_mask(const char *ethname, char *mask);
int get_eth_mac(const char *ethname, char *mac);
int get_eth_info(const char *ethname, eth_info_t *info);


#endif

