#ifndef _HTTP_H_
#define _HTTP_H_

/* ulibc: __USE_GUN
 * glibs: _GNU_SOURCE
 */
#define _GNU_SOURCE
#include <string.h>
#include <math.h>
#include <syslog.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include "list.h"
#include "safe_free.h"
#include "err_quit.h"

#define HTTP   0
#define HTTPS  1

#define REQUEST           0
#define IS_REQUEST        REQUEST
#define RESPONSE          1
#define IS_RESPONSE       RESPONSE

#define DEFAULT_HTTP_PORT   80
#define DEFAULT_HTTPS_PORT  443
#define HTTP_PROXY_PORT     8082
#define HTTPS_PROXY_PORT    8083
#define LEN_SSL_RECORD      16384

/*
 * 关于PR的说明
 * 0-PR_NONE: 从header中无法分析出任何有效信息
 * 1-PR_TXT_LEN:        body_type ∈　text_table[],  content-length
 * 2-PR_TXT_CHUNK:      body_type ∈　text_table[],  chunked
 * 5-PR_TXT_NONE:       body_type ∈　text_table[], !content-length && !chunked
 * 3-PR_NONE_TXT_LEN:   body_type !∈　text_table[], content-length
 * 4-PR_NONE_TXT_CHUNK: body_type !∈　text_table[], chunked
 * 6-PR_NONE_TXT_NONE:  body_type !∈　text_table[], !content-length && !chunked
 */
#define PR_NONE          0
#define PR_LEN           1 
#define PR_CHUNK         2
#define PR_TXT_CHUNK     3
#define PR_TXT_LEN       4
#define PR_NONE_TXT_LEN  5
#define PR_NONE_TXT_CHK  6
#define PR_TXT_NONE      7
#define PR_NONE_TXT_NONE 8


#define ENCD_NONE      0
#define ENCD_GZIP      1
//not used
#define ENCD_BR
#define ENCD_DEFLATE
#define ENCD_COMPRESS



#define ENCD_KEEP      0
#define ENCD2FLATE     1

#define LEN_IP        16
#define LEN_METHOD    16  
#define LEN_URL       1024
#define LEN_VER       10
#define LEN_STAT_CODE 4
#define LEN_STAT_INFO 64

#define LEN_HOST         128
#define LEN_FIELD_KEY    64
#define LEN_FIELD_VALUE  960
#define LEN_LINE         1024

/* 一般来说请求头不会太长，这里认为长度不会超过4096 kbyte */
#define LEN_HEADER       4096
#define LEN_CHUNK        4096
#define LEN_BUF          1024
#define CHUNK 8192


/* seconds */
#define TIMEOUT_CONNECT  5
#define CLIENT_TIMEOUT   2

typedef struct _http_header{
	char   method[LEN_METHOD];
	char   url[LEN_URL];
	char   ver[LEN_VER];
	char   stat_code[LEN_STAT_CODE];
	char   stat_info[LEN_STAT_INFO];
    char   crlf[3];
    struct list_head head;
}http_header_t;

typedef struct _http_field
{
	char   key[LEN_FIELD_KEY];
	char   value[LEN_FIELD_VALUE];
	struct list_head list;
}http_field_t;


typedef struct content_type_text
{
    char *type;
}c_type_t;

typedef struct {
    int  chk_size;
    char *chk_ext;
    char chk_crlf[3];
    /* 非trailer */
    char *body;
    /* trailer */
    int  trl_size;
    char *trailer;
    char body_crlf[3];
    struct list_head list;
}http_chunk_t;

typedef struct {
    char ip[LEN_IP];
    SSL_SESSION *session;
    pthread_mutex_t lock;
    struct list_head list;
}proxy_sess_t;

/* 定义在http.c中 */
extern int proxy;
extern c_type_t text_table[];

extern int readn(int fd, SSL *ssl, void *buff, int n);
extern int read_line(int fd, SSL *ssl, char *buff, int cnt);
extern int read_http_header(int fd, SSL *ssl, char *buff, int cnt);
extern int my_write(int fd, SSL *ssl, const char *fmt, ...);

extern int parse_http_header(const char *buf, http_header_t *header);
extern int parse_http_field(const char *line, http_field_t *field);
extern void free_http_header(http_header_t **header);
extern int hex2dec(char *hex, unsigned int *dec);
extern int erase_nhex(char *chunk_size);
extern int get_pr_encd(struct list_head *head, int *pr, int *encd);
extern int get_host_port(http_header_t *header, char *host, short *port);
extern int is_http_req_rsp(http_header_t *header);
extern int http_header_tostr(http_header_t *header, char *buff);
extern int rewrite_clen_encd(struct list_head *head, int content_length, int gunzip);
extern int rewrite_encd(struct list_head *head, int encd);
struct list_head *read_all_chunk(int fd, SSL *ssl);
int read_parse_chunk(int fd, SSL* ssl, http_chunk_t *chunk);
int read_parse_chk_size_ext_crlf(int fd, SSL* ssl, http_chunk_t *chunk);
int read_parse_chk_body_crlf(int fd, SSL *ssl, http_chunk_t *chunk);
int is_empty_line(const char *line);
int http_chunk_to_buff(http_chunk_t *chunk, unsigned char **buf, unsigned int *len);
int http_all_chunk_to_buff(struct list_head *head, unsigned char **buff, unsigned int *len);
void free_http_chunk(http_chunk_t *chunk);
void free_chunk_list(struct list_head *head); 
extern int print_ssl_error(SSL *ssl, int ret, const char *remark);
SSL_SESSION *get_ssl_session(struct list_head *head, const char *ip);
int set_ssl_sesstion(struct list_head *head, const char *ip, SSL_SESSION *session);

#endif

