#include "http.h"

c_type_t text_table[] = {
    { "text/h323"			   },
    { "text/asa"			   },
    { "text/asp"			   },
    { "text/xml"			   },
    { "text/x-component"	   },
    { "text/html"			   },
    { "text/x-vcard"		   },
    { "text/scriptlet"		   },
    { "text/vnd.wap.wml"	   },
    { "text/iuls"			   },
    { "text/plain"			   },
    { "text/vnd.rn-realtext"   },
    { "text/vnd.rn-realtext3d" },
    { "text/x-ms-doc"		   },
    { "text/webviewhtml"	   },
#ifdef DEBUG
    { "text/css"			   },
    { "application/javascript" },
    { "text/javascript"		   },
#endif
    { "application/VIID+JSON"  },   /* 2018-05-10,凌轩图像认证 */
    { "application/atom+xml"   },
    { "application/json"       },   /* 南京茂业 */
    { "application/soap+xml"   },   /* 南京茂业 */
    { "application/rdf+xml"    },
    { "application/rss+xml"    },
    { "application/xhtml+xml"  },
    { "application/xml-dtd"    },
    { "application/xop+xml"    },
    { "application/rdf+xml"    },
    { "application/x-www-form-urlencoded"},  /* 自己测试表单提交-chrome */
    { "application/xml"        },  /* 海康枪式摄像头 */
    {NULL}
};



/*
 * return:
 *  -1: err
 *  >0: ok
 */
http_obj_t *http_obj_create(void)
{
    http_obj_t *obj = (http_obj_t *)calloc(1, sizeof(*obj));
    if(NULL == obj) {
        perror("calloc()");
        return NULL;
    }
    return obj;
}

int http_obj_init(http_obj_t *obj, int fd)
{
    obj->fd = fd;
    obj->state = STATE_OBJ_HDR;
    return http_header_init(&(obj->header));
}

/*
 * 用哈希表或者位图优化obj
 */
http_obj_t *http_obj_get(struct list_head *head, int fd)
{
    struct list_head *pos;
    list_for_each(pos, head) {
        http_obj_t *obj = list_entry(pos, http_obj_t, list);
        printf("fd = %d, obj->fd = %d\n", fd, obj->fd);
        if(fd == obj->fd) {
            return obj;
        }
    }
    return NULL;
}

void http_obj_free(http_obj_t *obj)
{
    free_http_header(&(obj->header));
}


int http_obj_reset(http_obj_t *obj)
{
    http_obj_free(obj);
    obj->state = STATE_OBJ_HDR;
    return http_header_init(&(obj->header));
}



int http_parse_firstline(http_header_t *header)
{
    char *line = header->line.buff;
    if(is_empty_line(line, strlen(line))) {
        return _PARSELINE_BAD_FIRST;
    }
    int ret;
    char str[LEN_METHOD + LEN_VER] = {0};
    char mid[LEN_URL + LEN_STAT_CODE] = {0};
    char end[LEN_VER + LEN_STAT_INFO] = {0};
    char *format = "%s %s";
    ret = sscanf(line, format, str, mid);
    if(ret != 2) {
        printf("parse_http_header: message line ret = %d != 2\n", ret);
        return _PARSELINE_BAD_FIRST;
    }
    char *m = strstr(line, mid);
    if(NULL == m) {
        printf("parse_http_header: mid wrong\n");
        return _PARSELINE_BAD_FIRST;
    }
    strcpy(end, m+strlen(mid)); /*end包含空格*/ 

    if(atoi(mid) > 0) {
        strcpy(header->ver, str);
        strcpy(header->stat_code, mid);
        strcpy(header->stat_info, end);
    }
    else {
        strcpy(header->method, str);
        strcpy(header->url, mid);
        strcpy(header->ver, end);
    }
    return _PARSELINE_CON;
}


int http_parse_field(http_header_t *header)
{
    /* Host: 192.168.1.33 */
    /* Date: 2017.09.20 11:33:33 */
#ifdef FUNC
    printf("==========start http_parse_field()==========\n");
#endif
    char *line = header->line.buff;
    if(is_empty_line(line, strlen(line))) {
        printf("parse field meet empty line\n");
        strncpy(header->crlf, line, strlen(line));

        /* 计算pr */
        if(header->has_type) {
            if(header->is_txt) {
                header->pr = header->content_chk?PR_TXT_CHUNK:(header->content_len>0?PR_TXT_LEN:PR_TXT_NONE);
            }
            else {
                header->pr = header->content_chk?PR_NONE_TXT_CHK:(header->content_len?PR_NONE_TXT_LEN:PR_NONE_TXT_NONE);
            }

        }
        return _PARSELINE_EPT;
    }
    char *p = strchr(line, ':');
    if(NULL == p) {
        printf("cannot parse line[%s]\n", line);
        return _PARSELINE_BAD_FIELD;
    }
    http_field_t *field = (http_field_t *)calloc(1, sizeof(*field));
    if(NULL == field) {
        perror("calloc()");
        return _PARSELINE_ERR;
    }
    strncpy(field->key, line, p-line+1);  /* include ':' */
    strcpy(field->value, p+1);
    list_add_tail(&(field->list), &(header->head));

    /* 顺便计算各个标志位 */
    if(strcasestr(field->key, "Content-length")) {
        header->content_len = atoi(field->value);
    }

    if (strcasestr(field->key, "Content-type")) {
#ifdef DEBUG_HTTP
        printf("\033[32m");
        printf("[%s%s]\n", field->key, field->value);
        printf("\033[0m");
#endif
        header->has_type = 1;
        header->is_txt = is_type_txt(field->value);
    }
    if (strcasestr(field->key, "Transfer-encoding") && strcasestr(field->value, "chunked")) {
#ifdef DEBUG_HTTP
        printf("\033[32m");
        printf("[%s%s]\n", field->key, field->value);
        printf("\033[0m");
#endif
        header->is_chk = 1;
    }

    if (strcasestr(field->key, "Content-Encoding")) {
#ifdef DEBUG_HTTP
        printf("\033[32m");
        printf("[%s%s]\n", field->key, field->value);
        printf("\033[0m");
#endif
        if (strcasestr(field->value, "gzip")) {
            header->encd = ENCD_GZIP;
        }
        /*
         * not used
         else if(strcasestr(field->value, "br")) {
         header->encd = ENCD_BR;
         }
         else if(strcasestr(field->value, "deflate")) {
         header->encd = ENCD_DEFLATE;
         }
         else if(strcasestr(field->value, "compress")) {
         header->encd = ENCD_COMPRESS;
         }
         */
        else {
            header->encd = ENCD_NONE;
        }
    }


#ifdef FUNC
    printf("==========finish parse_http_field()==========\n");
#endif
    return _PARSELINE_CON;

}


/*
 * return:
 *  -1: err
 *  >0: ok
 */
int http_header_init(http_header_t *header)
{
    init_list_head(&(header->head));
    header->state = STATE_HEADER_RECV;
    header->state_line = STATE_LINE_FIRST;
    return line_calloc(&(header->line), LINE_MAX);
}

void free_http_header(http_header_t *header)
{
    /* 避免重复释放
     * 写成了if(header == NULL), 导致第二次释放header非法访问了内存
     * 这个小bug害的我从15:00一直调试到23:00．都没能回家陪女朋友
     */
    if(header == NULL) {
        printf("cannot free_http_header: do not double free http_header\n");
        return;
    }
    SAFE_FREE(header->line.buff);
    struct list_head *head = &(header->head);
    struct list_head *pos =  head->next;
    struct list_head *tmp = NULL;
    while(pos != head) {
        tmp = pos->next;
        http_field_t *field = list_entry(pos, http_field_t, list);
        SAFE_FREE(field);
        pos = tmp;
    }
}


/* get_pr_encd()
 * return : content-length
 */
int get_pr_encd(http_header_t *header, int *pr)
{
#ifdef FUNC
    printf("==========start get_pr_encd()==========\n");
#endif
    int len = 0;
    int has_c_type = 0;
    int is_clen = 0;
    int is_chunk = 0;
    struct list_head *pos = NULL;
    *pr = PR_NONE;
    header->encd = ENCD_NONE;
    list_for_each(pos, &(header->head)){
        http_field_t *field = list_entry(pos, http_field_t, list);

        /* openwrt 使用的是ulibc，包含strcasestr函数, glibc也包含 */
        if (strcasestr(field->key, "Content-type")) {
#ifdef DEBUG_HTTP
            printf("\033[32m");
            printf("[%s%s]\n", field->key, field->value);
            printf("\033[0m");
#endif
            has_c_type = 1;
        }

        if (strcasestr(field->key, "Content-length")) {
#ifdef DEBUG_HTTP
            printf("\033[32m");
            printf("[%s%s]\n", field->key, field->value);
            printf("\033[0m");
#endif
            is_clen = 1;
            len = (int) atoll(field->value);
        }

        if (strcasestr(field->key, "Transfer-encoding") && strcasestr(field->value, "chunked")) {
#ifdef DEBUG_HTTP
            printf("\033[32m");
            printf("[%s%s]\n", field->key, field->value);
            printf("\033[0m");
#endif
            is_chunk = 1;
        }

        if (strcasestr(field->key, "Content-Encoding"))
        {
#ifdef DEBUG_HTTP
            printf("\033[32m");
            printf("[%s%s]\n", field->key, field->value);
            printf("\033[0m");
#endif
            if (strcasestr(field->value, "gzip")) {
                header->encd = ENCD_GZIP;
            }
            /*
             * not used
             else if(strcasestr(field->value, "br")) {
             header->encd = ENCD_BR;
             }
             else if(strcasestr(field->value, "deflate")) {
             header->encd = ENCD_DEFLATE;
             }
             else if(strcasestr(field->value, "compress")) {
             header->encd = ENCD_COMPRESS;
             }
             */
            else {
                header->encd = ENCD_NONE;
            }
        }
    }

    if(has_c_type) {
        *pr = is_chunk?PR_HTTP_CHK:(is_clen?PR_HTTP_LEN:PR_HTTP_NONE);
    }
#ifdef FUNC
    printf("==========finish get_pr_encd()==========\n");
#endif
    return len;
}


/* return:
 *  -1 : 没有找到host字段
 *  0  : ok 
 */
int get_host_port(http_header_t *header, char *host, unsigned short *port)
{
#ifdef FUNC
    printf("==========start get_host_port()==========\n");
#endif
    if(NULL == header) {
        return -1;
    }
    int ret;
    struct list_head *head = &(header->head);
    struct list_head *pos = NULL;

    list_for_each(pos, head){
        http_field_t *field = list_entry(pos, http_field_t, list);

        if (strcasestr(field->key, "Host"))
        {
            /* [Host :| 192.168.1.1:80 ]  */
            /* host中不能有space */
            char *start = field->value;
            while(*start == ' ') start++;

            if(strchr(start, ':')) {
                char *format = "%[^:]:%[0-9]";
                char s_port[10] = {0};
                ret = sscanf(start, format, host, s_port);
                if(ret == 2) {
                    printf("s_port=[%s]\n", s_port);
                    *port = (unsigned short) atoi(s_port);  //aoti(" 123 ") also works well
                }
                else if(ret == 1) {
                    syslog(LOG_INFO, "get_host_port [%s] sscanf only return 1, make port default 80/443", start);
                    *port = DEFAULT_HTTP_PORT;
                }
                else {
                    syslog(LOG_INFO, "get_host_port [%s] sscanf error", start);
                    return -1;
                }
            }
            else {
                /* [192.168.1.1 \r\n] */
                if(1 != sscanf(start, "%s[^\r^\n^ ]", host)) {
                    syslog(LOG_INFO, "get_host_port [%s] sscanf error", start);
                    return -1;
                }
                *port = DEFAULT_HTTP_PORT;
            }
            return 0;
        }
    }
#ifdef FUNC
    printf("==========finish get_host_port()==========\n");
#endif
    return -1;
}

int is_http_req_rsp(http_header_t *header)
{
    return atoi(header->stat_code)>0?IS_RESPONSE:IS_REQUEST;
}

/*
 * 使用了sprintf()可能会引起缓冲区溢出, 确保缓冲区够大
 * 后期再优化
 */

int http_header_tostr(http_header_t *header, char *buff)
{
#ifdef FUNC
    printf("==========start http_header_tostr()==========\n");
#endif
    /* 不对buff进行检查，确保buff够大 */
#ifdef TIME_COST
    struct timeval strt;
    struct timeval end;
    gettimeofday(&strt, NULL);
#endif
    int req_rsp = is_http_req_rsp(header);
    if(req_rsp == IS_REQUEST) {
        sprintf(buff, "%s %s%s", header->method, header->url, header->ver);
    }
    else if(req_rsp == IS_RESPONSE) {
        sprintf(buff, "%s %s%s", header->ver, header->stat_code, header->stat_info);
    }
    else {
        printf("http_header_tostr: neither request or response\n");
        return -1;
    }


    struct list_head *pos;
    struct list_head *head = &(header->head);
    list_for_each(pos, head) {
        http_field_t *field = list_entry(pos, http_field_t, list);
        strcat(buff, field->key);
        strcat(buff,  field->value);
    }
    strcat(buff, header->crlf);
    printf("\nhttp_header_tostr:\n[%s]\n", buff);
#ifdef TIME_COST
    gettimeofday(&end, NULL);
    printf("execute header_to_str use time: start=%lds %ldms, end in %lds %ldms\n", strt.tv_sec, strt.tv_usec, end.tv_sec, end.tv_usec);
#endif
#ifdef FUNC
    printf("==========finish http_header_tostr()==========\n");
#endif
    return 0;
}


/* return:
 * 0: not rewrite
 * 1: rewrite
 */
int rewrite_clen_encd(http_header_t *header, int content_length, int gunzip)
{
#ifdef FUNC
    printf("==========start rewrite_clen_encd()==========\n");
#endif
    struct list_head *head = &(header->head);
    struct list_head *pos = head->next;
    while(pos != head) {
        http_field_t *field = list_entry(pos, http_field_t, list);
        if(strcasestr(field->key, "Content-length")) {
            int len = strlen(field->value);
            int cr = (field->value)[len-2]=='\r'?1:0;
            int lf = (field->value)[len-1]=='\n'?1:0;
            if(!lf){
                printf("content-length没有行结束标志\n");
                return 0;
            }
            memset(field->value, 0, LEN_FIELD_VALUE);
            sprintf(field->value, "%d", content_length);
            if(cr) {
                strcat(field->value, "\r\n");
            }
            else {
                strcat(field->value, "\n");
            }
        }
        if(strcasestr(field->key, "Content-encoding")) {
            if(gunzip == ENCD2FLATE) {
                /* 解压之后删除content-encoding */
                struct list_head *tmp = pos->next;
                list_del(pos);
                SAFE_FREE(field);
                pos = tmp->prev;
                header->encd = ENCD_NONE;
            }
        }
        pos = pos->next;
    }
#ifdef FUNC
    printf("==========finish rewrite_clen_encd()==========\n");
#endif
    return 0;
}

int rewrite_encd(http_header_t *header, int encd)
{
#ifdef FUNC
    printf("==========start rewrite_c_encd()==========\n");
#endif
    struct list_head *head = &(header->head);
    struct list_head *pos = head->next;
    while(pos != head) {
        http_field_t *field = list_entry(pos, http_field_t, list);
        if(strcasestr(field->key, "Content-encoding")) {
            if(encd == ENCD2FLATE) {
                struct list_head *tmp = pos->next;
                list_del(pos);
                SAFE_FREE(field);
                pos = tmp->prev;
            }
            else if(encd == ENCD_KEEP) {
                /*memset(field->value, 0, LEN_FIELD_VALUE);
                  sprintf(field->value, "%s", "gzip");
                  */
                ;
            }
        }
        pos = pos->next;
    }
#ifdef FUNC
    printf("==========finish rewrite_c_encd()==========\n");
#endif
    return 0;
}


