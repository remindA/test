/*
 * =====================================================================================
 *
 *       Filename:  utils_net.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年07月19日 20时09分50秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#ifndef _UTILS_NET_H_
#define _UTILS_NET_H_

/*
 * return :
 *  failed: -1
 *  ok    : fd
 */
int sock_create_tcp(const char *ip, unsigned short port);


/*
 * return :
 *  failed: -1
 *  ok    : fd
 */
int sock_connect(const char *ip, unsigned short port);


/*
 * 连接时设置非阻塞
 * return的fd是阻塞的
 * return:
 *  failed: -1
 *  ok    : 0
 */
int sock_connect_timeout(const char *ip, unsigned short port, int timeout)

    
/*
 * return:
 * failed : -1
 * ok     : old_flags
 */
int sock_set_nonblock(int fd);



/*
 * return:
 *   0  : ok
 *   -1 : failed
 */
int sock_set_reuseraddr(int _fd);


/*
 * return:
 *  failed: -1
 *  ok    : 0
 * get noting, if ip == NULL && port == NULL
 * only get ip: if port == NULL
 * only get port, if ip == NULL
 * get both ip and port
 */
int sock_get_peeraddr(int fd, char *ip, unsigned short *port);


/*
 * return:
 *  failed: -1
 *  ok    : 0
 * get noting, if ip == NULL && port == NULL
 * only get ip: if port == NULL
 * only get port, if ip == NULL
 * get both ip and port
 */
int get_local_addr(int fd, char *ip, unsigned short *port);

#endif

