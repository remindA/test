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
 * read_http_header()
 * return : 
 *  -1 : failed
 *  >0 : actual num readed
 */
int read_http_header(int fd, char *buff, int cnt)
{
#ifdef FUNC
    printf("==========start _read_http_header()==========\n");
#endif
    int ret = 0;
    int tot = 0;
#ifdef TIME_COST
    struct timeval strt;
    struct timeval end;
    gettimeofday(&strt, NULL);
#endif
    char ip[16] = {0};
    unsigned short port = 0;
    get_peer_addr(fd, ip, &port);
    while (1){
         char line[LEN_LINE] = {0};
         ret = read_line(fd, line, sizeof(line)-1);
         if(ret <= 0) {
             return ret;
         }
         strcat(buff, line);
         tot += ret;
         if(is_empty_line(line)) {
             break;
         }
    }
#ifdef TIME_COST
    gettimeofday(&end, NULL);
    printf("execute _read_http_header use time: start=%lds %ldms, end in %lds %ldms\n",
            strt.tv_sec, strt.tv_usec, end.tv_sec, end.tv_usec);
#endif
#ifdef FUNC
    printf("==========finish _read_http_header()==========\n");
#endif
    return tot;
}


/* parse_http_header()
 * return :
 *     0 : ok
 *     -1: failed
 * 解析时，所有的':' 和'\r\n'都保留下来了
 */
int parse_http_header(const char *buf, http_header_t *header)
{
#ifdef FUNC
    printf("==========start parse_http_header()==========\n");
#endif
    if(buf == NULL) {
        return -1;
    }
    int ret;
    char *start;
    char *crlf;
    start = (char *)buf;
    if((crlf = strchr(start, '\n'))) {
        char line[LEN_LINE] = {0};
        char str[LEN_METHOD + LEN_VER] = {0};
        char mid[LEN_URL + LEN_STAT_CODE] = {0};
        char end[LEN_VER + LEN_STAT_INFO] = {0};
        strncpy(line, start, crlf+1-start);  /* include '\n' */
#ifdef DEBUG_HTTP
        printf("parse_http_header, first line=[%s]\n", line);
#endif
        char *format = "%s %s";
        ret = sscanf(line, format, str, mid);
        if(ret != 2) {
#ifdef DEBUG_HTTP
            printf("parse_http_header: message line ret = %d != 2\n", ret);
#endif
            syslog(LOG_INFO, "parse_http_header ret is not 2");
            return -1;
        }
        char *m = strstr(line, mid);
        if(NULL == m) {
            printf("parse_http_header: mid wrong\n");
            return -1;
        }
        strcpy(end, m+strlen(mid)); /*end包含空格*/ 
        printf("str=[%s], len=%lu\n", str, strlen(str));
        printf("mid=[%s], len=%lu\n", mid, strlen(mid));
        printf("end=[%s], len=%lu\n", end, strlen(end));

        if(atoi(mid) > 0) {
            printf("a\n");
            strcpy(header->ver, str);
            printf("b\n");
            strcpy(header->stat_code, mid);
            printf("c\n");
            strcpy(header->stat_info, end);
            printf("d\n");
        }
        else {
            printf("A\n");
            strcpy(header->method, str);
            printf("B\n");
            strcpy(header->url, mid);
            printf("C\n");
            strcpy(header->ver, end);
            printf("D\n");
        }
        start = crlf + 1;
        printf("3\n");
    }
    /* field */
    while((crlf = strchr(start, '\n'))) {

        printf("4\n");
        char line[LEN_LINE] = {0};
        strncpy(line, start, crlf-start+1);  /*include '\n'*/
#ifdef DEBUG_HTTP
        printf("[%s]\n", line);
#endif
        if(is_empty_line(line)) {
            strcpy(header->crlf, line);
            break;
        }

        http_field_t *field = (http_field_t *)calloc(1, sizeof(http_field_t));
        if(parse_http_field(line, field) < 0) {
#ifdef DEBUG_HTTP
            printf("cannot parse_http_line[%s]\n", line);
#endif
            syslog(LOG_INFO, "cannot parse_http_line[%s]\n", line);
            free_http_header(header);
            return -1;
        }
        else {
            list_add_tail(&(field->list), &(header->head)); 
        }
        start = crlf + 1;
    }
#ifdef FUNC
    printf("==========finish parse_http_header()==========\n");
#endif
    return 0;
}

/* parse_http_field()
 * return :
 *     0 : ok
 *     -1: failed
 */
int parse_http_field(const char *line, http_field_t *field)
{
    /* Host: 192.168.1.33 */
    /* Date: 2017.09.20 11:33:33 */
#ifdef FUNC
    printf("==========start parse_http_field()==========\n");
#endif
    char *p = strchr(line, ':');
    if(NULL == p) {
        return -1;
    }
    strncpy(field->key, line, p-line+1);  /* include ':' */
    strcpy(field->value, p + 1);
#ifdef FUNC
    printf("==========finish parse_http_field()==========\n");
#endif
    return 0;
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
    struct list_head *head = &(header)->head;
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
    

    printf("first line[%s]\n", buff);
    struct list_head *pos;
    struct list_head *head = &(header->head);
    list_for_each(pos, head) {
        http_field_t *field = list_entry(pos, http_field_t, list);
        strcat(buff, field->key);
        if(strcasestr(field->key, "server")) {
            strcat(buff, "NIUYABEN\r\n");
        }
        else {
            strcat(buff,  field->value);
        }
    }
    strcat(buff, header->crlf);
#ifdef DEBUG_HTTP
    printf("\nhttp_header_tostr:\n[%s]\n", buff);
#endif
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


int read_all_chunk(int fd, struct list_head *head)
{
#ifdef FUNC
    printf("==========start read_all_chunk()==========\n");
#endif
    if(head == NULL) {
        return -1;
    }
    while(1) {
        http_chunk_t *chunk = (http_chunk_t *)calloc(1, sizeof(http_chunk_t));
        if(NULL == chunk) {
            free_chunk_list(head);
            return -1;
        }
        if(read_parse_chunk(fd, chunk) <= 0) {
            free_chunk_list(head);
            return -1;
        }
        list_add_tail(&(chunk->list), head);
        if(chunk->chk_size <= 0) {
            break;
        }
    }
#ifdef FUNC
    printf("==========finish read_all_chunk()==========\n");
#endif
    return 1;
}


/*
 * 读取一个chunk并
 * return:  ok    : 1  
 *          failed: <=0
 */ 
int read_parse_chunk(int fd, http_chunk_t *chunk)
{
    int ret;
    ret = read_parse_chk_size_ext_crlf(fd, chunk);
    if(ret <= 0) {
        return ret;
    }
    return read_parse_chk_body_crlf(fd, chunk);
}

int read_parse_chk_size_ext_crlf(int fd, http_chunk_t *chunk)
{
    int ret;
    char line[LEN_LINE] = {0};
    ret = read_line(fd, line, sizeof(line));
    if(ret <=0) {
        return ret;
    }
    /* size ext crlf */
    /* ext: 
     * "ext_name":"ext_value"
     *
     */
    char size[64] = {0};
    printf("chunk_size=[%s]\n", line);
    ret = sscanf(line, "%[0-9a-zA-Z]", size);
    if(1 != ret) {
        printf("chk_size error\n");
        return -1;
    }
    hex2dec(size, (unsigned int *)&(chunk->chk_size)); 
    printf("size=%d\n", chunk->chk_size);

    char *lf = strstr(line, "\n");
    char *crlf = strstr(line, "\r\n");
    crlf = crlf?crlf:lf;
    if(NULL == crlf) {
        printf("chk_crlf error\n");
        return -1;
    }
    if(strlen(crlf) > sizeof(chunk->chk_crlf)-1) {
        printf("chk_crlf length over 2, [%s]\n", crlf);
        return -1;
    }
    strcpy(chunk->chk_crlf, crlf);

    char *split = strchr(line, ';');
    if(split) {
        chunk->chk_ext = (char *)calloc(1, crlf-split+1);
        strncpy(chunk->chk_ext, split, crlf-split);
    }
    return 1;
}


int read_parse_chk_body_crlf(int fd, http_chunk_t *chunk)
{
    /* 非trailer */
    /* 可能是压缩过的内容:w */
    if(chunk->chk_size > 0) {
        int ret1, ret2;
        chunk->trl_size = 0;
        chunk->body = (char *)calloc(1, chunk->chk_size);
        if(NULL == chunk->body) {
            return ERR_CHK_MEM;
        }
        ret1 = readn(fd, chunk->body, chunk->chk_size);
        if(ret1 <=0) {
            SAFE_FREE(chunk->body);
            printf("readn in read_parse_chk_body_crlf return %d\n", ret1);
            return ret1;
        }
        if(ret1 != chunk->chk_size) {
            printf("chunk body: should read %d, actual read %d\n", chunk->chk_size, ret1);
        }
        //printf("chunk->body is [%s]\n", chunk->body);
        ret2 = read_line(fd, chunk->body_crlf, sizeof(chunk->body_crlf));
        if(ret2 <=0) {
            SAFE_FREE(chunk->body);
            printf("read_line in read_parse_chk_body_crlf return %d\n", ret2);
            return ret2;
        }
        printf("read_body: is_empty_line=%d, [%s]\n", is_empty_line(chunk->body_crlf), chunk->body_crlf);
        return ret1;
    }
    /* trailer */
    else {
        int ret;
        int tot = 0;
        char line[LEN_LINE] = {0};
        while((ret = read_line(fd, line, sizeof(line))) > 0){
            if(is_empty_line(line)) {
                chunk->trl_size = tot;
                memcpy(chunk->body_crlf, line, ret);
                break;
            }
            else{
                chunk->trailer = realloc(chunk->trailer, tot+ret);
                memcpy(chunk->trailer+tot, line, ret);
                tot += ret;
            }
            memset(line, 0, sizeof(line));
        }
        return ret;
    }
}



int http_chunk_to_buff(http_chunk_t *chunk, unsigned char **buf, unsigned int *len)
{
    /* 32位操作系统十六进制字符串最长8 */
    char size[64] = {0};
    sprintf(size, "%x", chunk->chk_size);
    *len = strlen(size) + (chunk->chk_ext?strlen(chunk->chk_ext):0) +
        strlen(chunk->chk_crlf) + chunk->chk_size + chunk->trl_size +
        strlen(chunk->body_crlf);
    *buf = (unsigned  char *)calloc(1, *len);
    if(NULL == *buf) {
        perror("calloc in http_chunk_to_buf");
        return -1;
    }
    int offset = 0; 
    memcpy(*buf + offset, size, strlen(size));
    offset += strlen(size);
    if(chunk->chk_ext) {
        memcpy(*buf + offset, chunk->chk_ext, strlen(chunk->chk_ext));
        offset += strlen(chunk->chk_ext);
    }
    memcpy(*buf + offset, chunk->chk_crlf, strlen(chunk->chk_crlf));
    offset += strlen(chunk->chk_crlf);
    if(chunk->chk_size > 0) {
        memcpy(*buf + offset, chunk->body, chunk->chk_size);
        offset += chunk->chk_size;
    }
    if(chunk->trl_size > 0) {
        memcpy(*buf + offset, chunk->trailer, chunk->trl_size);
        offset += chunk->trl_size;
    }
    memcpy(*buf + offset, chunk->body_crlf, strlen(chunk->body_crlf));
    offset += strlen(chunk->body_crlf);
    return 0;
}


/*
 * http_all_chunk_to_buff:
 *  把所有chunk body拼接完整，放入到一个缓冲区,解压
 *  如果调用此函数，对每个chunk来说，ext是无用的
 *  trailer暂时去掉
 *  转发按照协议规定进行
 *  [size]\r\n
 *  [body]\r\n
 *  0\r\n
 *  \r\n
 */ 
int http_all_chunk_to_buff(struct list_head *head, unsigned char **buff, unsigned int *len)
{
    *len = 0;
    struct list_head *pos;
    list_for_each(pos, head) {
        http_chunk_t *chunk = list_entry(pos, http_chunk_t, list);
        if(chunk->chk_size > 0){
            *buff = (unsigned char *)realloc(*buff, *len+chunk->chk_size);
            if(NULL == *buff) {
                perror("realloc, in http_chunk_all_to_buff");
                return -1;
            }
            memcpy(*buff + *len, chunk->body, chunk->chk_size);
            *len += chunk->chk_size;
        }
    }
    return 0;
}

void free_http_chunk(http_chunk_t *chunk)
{
    SAFE_FREE(chunk->chk_ext);
    SAFE_FREE(chunk->body);
    SAFE_FREE(chunk->trailer);
}

void free_chunk_list(struct list_head *head) 
{
    struct list_head *tmp;
    struct list_head *pos = head->next;
    while(pos != head) {
        http_chunk_t *chunk = list_entry(pos, http_chunk_t, list);
        tmp = pos->next;
        list_del(pos);
        pos = tmp;
        free_http_chunk(chunk);
        SAFE_FREE(chunk);
    }
}

