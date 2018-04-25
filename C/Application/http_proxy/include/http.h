#ifndef _HTTP_H_
#define _HTTP_H_

#include <math.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include "str_replace.h"
#include "pad_rplstr.h"
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
#define HTTPS_PROXY_PORT    8888
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
#define PR_TXT_CHUNK     1
#define PR_TXT_LEN       2
#define PR_NONE_TXT_LEN  3
#define PR_NONE_TXT_CHK  4
#define PR_TXT_NONE      5
#define PR_NONE_TXT_NONE 6


#define ENCD_FLATE     0
#define ENCD_GZIP      1
#define ENCD_NONE      ENCD_FLATE


#define GZIP2GZIP      0
#define GZIP2FLATE     1

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
    char type[32];
}c_type_t;


/* 定义在http.c中 */
extern int proxy;
extern c_type_t text_table[];

extern int readn(int fd, SSL *ssl, void *buff, int n);
extern int read_line(int fd, SSL *ssl, char *buff, int cnt);
extern int read_double_crlf(int fd, SSL *ssl, char *buff, int cnt);
extern int my_write(int fd, SSL *ssl, const char *fmt, ...);
extern int print_ssl_error(SSL *ssl, int ret, const char *remark);

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
extern int rewrite_c_encd(struct list_head *head, int encd);

#endif

