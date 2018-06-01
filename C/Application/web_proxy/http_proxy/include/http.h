#ifndef _HTTP_H_
#define _HTTP_H_

#include <math.h>
/* ulibc: __USE_GUN
 * glibs: _GNU_SOURCE
 */
#include <string.h>
#include <syslog.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "list.h"
#include "safe_free.h"
#include "err_quit.h"
#include "socket_tools.h"

#define REQUEST           0
#define IS_REQUEST        REQUEST
#define RESPONSE          1
#define IS_RESPONSE       RESPONSE

#define DEFAULT_HTTP_PORT   80
#define DEFAULT_HTTPS_PORT  443
#define HTTP_PROXY_PORT     8082
#define HTTPS_PROXY_PORT    8083
#define LEN_SSL_RECORD      16384

#define PR_NONE          0
#define PR_HTTP_LEN      1
#define PR_HTTP_CHK      2
#define PR_HTTP_NONE     3

#define ERR_CHK_MEM      -10
#define ERR_BODY_MEM      -10


#define ENCD_NONE      0
#define ENCD_GZIP      1
//not used
#define ENCD_BR        2
#define ENCD_DEFLATE   3
#define ENCD_COMPRESS  4



#define ENCD_KEEP      0
#define ENCD2FLATE     1

#define LEN_METHOD    32  
#define LEN_URL       1024
#define LEN_VER       64
#define LEN_STAT_CODE 32
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
    int    encd;
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


/* 定义在http.c中 */
extern int proxy;
extern c_type_t text_table[];

extern int read_http_header(int fd, char *buff, int cnt);
extern int parse_http_header(const char *buf, http_header_t *header);
extern int parse_http_field(const char *line, http_field_t *field);
extern void free_http_header(http_header_t *header);
extern int get_pr_encd(http_header_t *header, int *pr);
extern int get_host_port(http_header_t *header, char *host, unsigned short *port);
extern int is_http_req_rsp(http_header_t *header);
extern int http_header_tostr(http_header_t *header, char *buff);
extern int rewrite_clen_encd(http_header_t *header, int content_length, int encd_opt);
extern int rewrite_encd(http_header_t *header, int encd);
int read_all_chunk(int fd, struct list_head *head);
int read_parse_chunk(int fd, http_chunk_t *chunk);
int read_parse_chk_size_ext_crlf(int fd, http_chunk_t *chunk);
int read_parse_chk_body_crlf(int fd, http_chunk_t *chunk);
int http_chunk_to_buff(http_chunk_t *chunk, unsigned char **buf, unsigned int *len);
int http_all_chunk_to_buff(struct list_head *head, unsigned char **buff, unsigned int *len);
void free_http_chunk(http_chunk_t *chunk);
void free_chunk_list(struct list_head *head); 

#endif

