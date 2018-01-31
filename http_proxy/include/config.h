/*
 * =====================================================================================
 *
 *       Filename:  config.h
 *
 *    Description:  获取https_proxy.cfg, remap_table, regex_table
 *
 *        Version:  1.0
 *        Created:  2018年01月10日 14时31分02秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#ifndef _HENGSION_HTTP_CONFIG_H
#define _HENGSION_HTTP_CONFIG_H
#include "include.h"
#include "safe_free.h"
#include "str_replace.h"
#include "list.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <pthread.h>    /* for https session ticket */

#ifdef SR04I
#include "socket_tools.h"
#endif

#ifdef OpenWRT
#include <uci.h>
#endif

#define LEN_IP      16
#define REMAP_TABLE 1
#define REGEX_TABLE 2
#define MSQID_POOL  3



typedef struct _remap_entry
{
    int    direction;       /* 替换方向RESPONSE/REQUEST */
    char   before[LEN_IP];  /* 真实ip */
    char   after[LEN_IP];   /* 映射ip */
    SSL_SESSION *session;   /* for https session ticket  */
    pthread_mutex_t lock;  /* for session */
    struct list_head list;
}remap_entry_t;

typedef struct
{
    char  ip[LEN_IP];
    short port;
    pcre2_code *re;
    struct list_head list;
}regex_entry_t;



#ifdef SR04I
char *nvram_data;
#endif
struct list_head *get_remap_table_m(char *key);
struct list_head *get_regex_table_m(char *key);
pcre2_code *get_general_regex(char *key);
void free_remap_table(struct list_head **head);
void free_regex_table(struct list_head **head);
pcre2_code *get_re_by_host_port(struct list_head *head, char *host, short port);
char *get_ip_before_remap(struct list_head *head, const char *ip);

extern SSL_SESSION *get_ssl_session(struct list_head *head, const char *ip);
extern int set_ssl_session(struct list_head *head, const char *ip, SSL_SESSION *session); 

SSL_SESSION *SSL_SESSION_dup(SSL_SESSION *src);
SSL_SESSION *ssl_session_dup(SSL_SESSION *src, int ticket);
#endif

