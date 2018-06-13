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




/***** return *****/
enum {
    _OBJ_ERR = 0, 
    _OBJ_CLS,
    _OBJ_BAD,
    _OBJ_AGN
};

enum {
    _HEADER_ERR = 0,  
    _HEADER_CLS,
    _HEADER_BAD, 
    _HEADER_AGN,
    _HEADER_CON,
    _HEADER_END,
    __HEADER_MAX
};

enum {
    _PARSELINE_CON = 0,
    _PARSELINE_EPT,
    _PARSELINE_ERR,
    _PARSELINE_BAD_FIRST,
    _PARSELINE_BAD_FIELD
};

/***** state *****/

enum {
    STATE_OBJ_HDR = 0,
    STATE_OBJ_BDY,
    STATE_OBJ_SND,
    STATE_OBJ_ERR,
    STATE_OBJ_CLS,
    STATE_OBJ_BAD,
};

enum {
    STATE_HEADER_RECV = 0,
    STATE_HEADER_PARSE,
    STATE_HEADER_END,
};

enum {
    STATE_LINE_FIRST = 0,
    STATE_LINE_FIELD,
};



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

typedef struct _http_header{
    /* 保存第一行数据 */
    int  req_rsp;  
    char method[LEN_METHOD];
    char url[LEN_URL];
    char ver[LEN_VER];
    char stat_code[LEN_STAT_CODE];
    char stat_info[LEN_STAT_INFO];
    char crlf[3];

    /* header状态: recv, parse, end*/
    int state;

    /* 行缓冲区 */
    line_t line;
    /* 当前解析行的状态, firstline, fieldline */
    int state_line;

    /* 处理优先级和压缩格式 */
    int pr;
    int has_type;
    int is_txt;
    int content_chk;
    int content_len;
    int content_encd;

    struct list_head head;
}http_header_t;

//查找后期用哈希链表优化

/*
 * obj
 *      fd: 连接
 *      state: 当前的执行状态
 *      header: 请求header
 *      body: 请求body
 *
 *      rsphdr: 响应header
 *      srpbdy: 响应body
 */
typedef struct {
    int fd;
    int state;
    http_header_t reqhdr;
    http_body_t reqbdy;

    http_header_t rsphdr;
    http_body_t rspbdy;
    struct list_head list;
}http_obj_t;

http_obj_t *http_obj_create(void);
int http_obj_init(http_obj_t *obj, int fd);
http_obj_t *http_obj_get(struct list_head *head, int fd);
void http_obj_reset_state(http_obj_t *obj);
void http_obj_free(http_obj_t *obj);
int http_parse_firstline(http_header_t *header);
int http_parse_field(http_header_t *header);
int http_header_init(http_header_t *header);


extern void free_http_header(http_header_t *header);
extern int get_pr_encd(http_header_t *header, int *pr);
extern int get_host_port(http_header_t *header, char *host, unsigned short *port);
extern int is_http_req_rsp(http_header_t *header);
extern int http_header_tostr(http_header_t *header, char *buff);
extern int rewrite_clen_encd(http_header_t *header, int content_length, int encd_opt);
extern int rewrite_encd(http_header_t *header, int encd);

#endif

