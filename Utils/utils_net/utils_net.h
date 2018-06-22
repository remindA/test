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

/* 创建套接字 */
int create_socket(const char *ip, unsigned short port);
int create_socket_nonblock(const char *ip, unsigned short port);

/* 设置套接字 */
int set_socket(int fd, int flag);

/* 获取网卡信息 */
int get_eth_ip(const char *ethname, char *ip);
int get_eth_mask(const char *ethname, char *mask);
int get_eth_mac(const char *ethname, char *mac);
int get_eth_info(const char *ethname, eth_info_t *info);


#endif

