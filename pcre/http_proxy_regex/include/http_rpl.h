#ifndef _HTTP_RPL_H
#define _HTTP_RPL_H

#include "str_replace.h"
#include "pad_rplstr.h"
#include "list.h"
#include "safe_free.h"
#include "err_quit.h"
#include <strings.h>

#define REQUEST  0
#define RESPONSE 1

#define DEFAULT_SERVER_PORT  80
#define LEN_BODY      8196

#define LEN_METHOD    16  
#define LEN_URL       2083
#define LEN_VER       10
#define LEN_STAT_CODE 4
#define LEN_STAT_INFO 64

typedef struct _http_request
{
	char method[LEN_METHOD];
	char url[LEN_URL];
	char ver[LEN_VER];
	struct list_head head;
}http_request_t;


typedef struct _http_response
{
	char ver[LEN_VER];
	char stat_code[LEN_STAT_CODE];
	char stat_info[LEN_STAT_INFO];
	struct list_head head;
}http_response_t;

#define PR_NONE        0
#define PR_NONE_TXT    1
#define PR_CHUNKED     2
#define PR_CONTENT_LEN 3


#define LEN_FIELD_KEY    32
#define LEN_FIELD_VLAUE  2016
#define LEN_LINE         2048
typedef struct _http_field
{
	struct list_head list;
	char key[LEN_FIELD_KEY];
	char value[LEN_FIELD_VLAUE];
}http_field_t;


typedef struct content_type_text
{
    char type[32];
}c_type_t;

extern c_type_t text_table[];

extern int parse_http_request_header(int fd, http_request_t *req);
extern int parse_http_response_header(int s_fd, http_response_t *rsp);
extern int read_line(int fd, char *buff, int cnt);
extern ssize_t my_read(int fd, char *ptr);
extern ssize_t read_line2(int fd, void *buff, size_t maxlen);
extern ssize_t readn(int fd, void *buff, int n);

void parse_http_req_line(const char *line, http_request_t *req_line);
void parse_http_rsp_line(const char *line, http_response_t *rsp_line);
void parse_http_filed(const char *line, http_field_t *field);
extern int get_server_host_port(struct list_head *req_head, char *host, short *s_port);
extern size_t get_response_priority(struct list_head *rsp_head, int *pr);
#endif


