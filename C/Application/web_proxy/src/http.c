#include "http.h"

int proxy;
c_type_t text_table[] = {
    { "text/h323"			   },
    { "text/asa"			   },
    { "text/asp"			   },
    { "text/xml"			   },
    { "text/x-component"	   },
    { "text/html"			   },
    /*{ "text/javascript"		   }, */
    { "text/x-vcard"		   },
    { "text/scriptlet"		   },
    { "text/vnd.wap.wml"	   },
    { "text/iuls"			   },
    { "text/plain"			   },
    { "text/vnd.rn-realtext"   },
    { "text/vnd.rn-realtext3d" },
    { "text/x-ms-doc"		   },
    { "text/webviewhtml"	   },
    /*{ "text/css"			   },
      { "application/javascript" },
      */
    { "application/VIID+JSON"},     /* 2018-05-10,凌轩图像认证 */
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

static int _readn(int fd, void *buff, int n);
static int _read_line(int fd, char *buff, int cnt);
static int _read_http_header(int fd, char *buff, int cnt);
static int _readn_ssl(SSL *ssl, void *buff, int n);
static int _read_line_ssl(SSL *ssl, char *buff, int cnt);
static int _read_http_header_ssl(SSL *ssl, char *buff, int cnt);

/* return
 *      -1 : err
 *      0  : 什么都没读
 *      >0 : 实际读取的字节数
 * 还可能阻塞住
 * 如何处理Content-length与实际情况不符合的情况,是否要使用select超时机制
 */
int readn(int fd, SSL *ssl, void *buff, int n)
{
    return (proxy == HTTP)?_readn(fd, buff, n):_readn_ssl(ssl, buff, n);
}

int read_line(int fd, SSL *ssl, char *buff, int n)
{
    return (proxy == HTTP)?_read_line(fd, buff, n):_read_line_ssl(ssl, buff, n);
}


int read_http_header(int fd, SSL *ssl, char *buff, int n)
{
    return (proxy == HTTP)?_read_http_header(fd, buff, n):_read_http_header_ssl(ssl, buff, n);
}


static int _readn(int fd, void *buff, int n)
{
#ifdef FUNC
    printf("==========start _readn()==========\n");
#endif
    ssize_t nread;
    size_t nleft = n;
    char *ptr = buff;

    while (nleft > 0)
    {
        nread = read(fd, ptr, nleft);
        if (nread < 0)
        {
            if (errno == EINTR)
            {
                perror("readn read");
                continue;
            }
            else
            {
                perror("readn read");
                return -1;
            }
        }
        else if (nread == 0)
        {
            perror("readn 0");
            break;
        }
        nleft -= nread;
        ptr += nread;
    }
#ifdef FUNC
    printf("==========finish _readn()==========\n");
#endif
    return n - nleft;
}

//缺陷版,可以结合readn使用
static int _read_line(int fd, char *buff, int cnt)
{
#ifdef FUNC
    printf("==========start _read_line()==========\n");
#endif
    int tot_read = 0;
    int n = 0;
    char c = 0;

    while (1)
    {
        n = read(fd, &c, 1);
        if (n < 0)
        {
            perror("read()");
            if (errno == EINTR)
                continue;
            else
                return n;
        }
        else if (n == 0)
        {
            break;
        }
        else
        {
            if (tot_read < cnt - 1)
            {
                tot_read++;
                *buff++ = c;
            }
            //一行超过最大缓存长度的部分就被阶段了
            //需要修改
        }
        if (c == '\n')
            break;
    }
#ifdef FUNC
    printf("==========finish _read_line()==========\n");
#endif
    return tot_read;
}

/*
 * read_http_header()
 * return : 
 *  -1 : failed
 *  >0 : actual num readed
 *  header: 结束标志
 *      \r\n\r\n
 *      \n\n
 */
static int _read_http_header(int fd, char *buff, int cnt)
{
#ifdef FUNC
    printf("==========start _read_http_header()==========\n");
#endif
    int tot_read = 0;
    int n = 0;
    char c = 0;
    char *start = buff;
#ifdef TIME_COST
    struct timeval strt;
    struct timeval end;
    gettimeofday(&strt, NULL);
#endif
    while (1)
    {
        n = read(fd, &c, 1);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            else {
                perror("_read_http_header: read()");
                syslog(LOG_INFO, "_read_http_header时出错");
                return -1;
            }
        }
        else if (n == 0) {
            break;
        }
        else {
            if (tot_read < cnt - 1) {
                tot_read++;
                *buff++ = c;
#ifdef DEBUG_HTTP
                printf("%c", c);
#endif
            }
            //一行超过最大缓存长度的部分就被阶段了
            //需要修改
        }

        if (c == '\n' && tot_read >= 4)
        {
#ifdef DEBUG_HTTP
            printf("0x%02x 0x%02x 0x%02x 0x%02x\n", start[tot_read - 4], 
                    start[tot_read - 3], start[tot_read  - 2], start[tot_read - 1]);
#endif
            if('\r' == start[tot_read - 4] && '\n' == start[tot_read - 3] &&
                    '\r' == start[tot_read - 2] && '\n' == start[tot_read - 1]) {
                break;
            }
            if('\n' == start[tot_read - 2] && '\n' == start[tot_read - 1] ) {
                break;
            }
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
    return tot_read;
}


static int _readn_ssl(SSL *ssl, void *buff, int n)
{
#ifdef FUNC
    printf("==========start _readn_ssl()==========\n");
#endif
    ssize_t nread;
    size_t nleft = n;
    char *ptr = buff;

    while (nleft > 0)
    {
        nread = SSL_read(ssl, ptr, nleft);
        if (nread < 0)
        {
            if (errno == EINTR) {
                continue;
            }
            else {
                print_ssl_error(ssl, nread, "_readn_ssl()");
                return -1;
            }
        }
        else if (nread == 0)
        {
            perror("readn 0");
            break;
        }
        nleft -= nread;
        ptr += nread;
    }
#ifdef FUNC
    printf("==========finish _readn_ssl()==========\n");
#endif
    return n - nleft;
}

//缺陷版,可以结合readn使用
static int _read_line_ssl(SSL *ssl, char *buff, int cnt)
{
#ifdef FUNC
    printf("==========start _read_line()==========\n");
#endif
    int tot_read = 0;
    int n = 0;
    char c = 0;

    while (1)
    {
        n = SSL_read(ssl, &c, 1);
        if (n < 0)
        {
            print_ssl_error(ssl, n, "_read_line_ssl()");
            if (errno == EINTR) {
                continue;
            }
            else {
                return n;
            }
        }
        else if (n == 0)
        {
            break;
        }
        else
        {
            if (tot_read < cnt - 1)
            {
                tot_read++;
                *buff++ = c;
            }
            //一行超过最大缓存长度的部分就被阶段了
            //需要修改
        }
        if (c == '\n')
            break;
    }
#ifdef FUNC
    printf("==========finish _read_line_ssl()==========\n");
#endif
    return tot_read;
}

/*
 * read_http_header_ssl()
 * return : 
 *  -1 : failed
 *  >0 : actual num readed
 *  header: 结束标志
 *      \r\n\r\n
 *      \n\n
 */
static int _read_http_header_ssl(SSL *ssl, char *buff, int cnt)
{
#ifdef FUNC
    printf("==========start _read_http_header_ssl()==========\n");
#endif
    int tot_read = 0;
    int n = 0;
    char c = 0;
    char *start = buff;
#ifdef TIME_COST
    struct timeval strt;
    struct timeval end;
    gettimeofday(&strt, NULL);
#endif
    while (1)
    {
        n = SSL_read(ssl, &c, 1);
        if (n < 0) {
            print_ssl_error(ssl, n, "_read_http_header_ssl()");
            if (errno == EINTR) {
                continue;
            }
            else {
                return -1;
            }
        }
        else if (n == 0) {
            //print_ssl_error(ssl, n, "read_double_crlf");
            break;
        }
        else {
            if (tot_read < cnt - 1) {
                tot_read++;
                *buff++ = c;
#ifdef DEBUG_HTTP
                printf("%c", c);
#endif
            }
            //一行超过最大缓存长度的部分就被阶段了
            //需要修改
        }

        if (c == '\n' && tot_read >= 4) {
#ifdef DEBUG_HTTP
            printf("0x%02x 0x%02x 0x%02x 0x%02x\n", start[tot_read - 4], 
                    start[tot_read - 3], start[tot_read  - 2], start[tot_read - 1]);
#endif
            if('\r' == start[tot_read - 4] && '\n' == start[tot_read - 3] &&
                    '\r' == start[tot_read - 2] && '\n' == start[tot_read - 1]) {
                break;
            }
            if('\n' == start[tot_read - 2] && '\n' == start[tot_read - 1] )  {
                break;
            }
        }
    }
#ifdef TIME_COST
    gettimeofday(&end, NULL);
    printf("execute _read_http_header_ssl use time: start=%lds %ldms, end in %lds %ldms\n",
            strt.tv_sec, strt.tv_usec, end.tv_sec, end.tv_usec);
#endif
#ifdef FUNC
    printf("==========finish _read_http_header_ssl()==========\n");
#endif
    return tot_read;
}

int my_write(int fd, SSL *ssl, const char *fmt, ...)
{
#ifdef FUNC
    printf("========start my_write()=======\n");
#endif
    int wr = 0;
    int len;
    int left;
    int offset;
    int wr_tot = 0;
    unsigned char *buff;

#ifdef TIME_COST
    struct timeval strt;
    struct timeval end;
    gettimeofday(&strt, NULL);
#endif
    va_list ap;
    va_start(ap, fmt);
    while(*fmt) {
        switch(*fmt++) {
            case 'l':
                len = va_arg(ap, int);
                break;
            case 'd':
                buff = va_arg(ap, unsigned char *);
                left = len;
                offset = 0;
                while(left > 0) {
                    wr = (proxy == HTTPS)?SSL_write(ssl, buff + offset, left):write(fd, buff + offset, left);
                    if(wr < 0) {
#ifdef DEBUG
                        if(proxy == HTTPS) 
                            print_ssl_error(ssl, wr, "my_write");
                        else if(proxy == HTTP)
                            perror("write()");
#endif
                        return -1;
                    }
                    left   -= wr;
                    wr_tot += wr;
                    offset += wr;
                }
                break;
            default: 
                break;
        }
    }
    va_end(ap);
#ifdef TIME_COST
    gettimeofday(&end, NULL);
    printf("execute my_write use time: start=%lds %ldms, end in %lds %ldms\n", strt.tv_sec, strt.tv_usec, end.tv_sec, end.tv_usec);
#endif
#ifdef FUNC
    printf("========finish my_write()=======\n");
#endif
    return wr_tot;
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
        char *p = strchr(line, '\r');
        char *q = strchr(line, '\n');
        char *format = "%s %s %s";
        ret = sscanf(line, format, str, mid, end);
        printf("str=[%s], len=%d\n", str, strlen(str));
        printf("mid=[%s], len=%d\n", mid, strlen(mid));
        strcat(end, p?:q);
        printf("end=[%s], len=%d\n", end, strlen(end));
        if(ret != 3) {
#ifdef DEBUG_HTTP
            printf("parse_http_header: message line ret = %d != 3\n", ret);
#endif
            return -1;
        }

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
        start = crlf + 1;
    }
    /* field */
    while((crlf = strchr(start, '\n'))) {
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


void free_http_header(http_header_t **header)
{
    /* 避免重复释放
     * 写成了if(header == NULL), 导致第二次释放header非法访问了内存
     * 这个小bug害的我从15:00一直调试到23:00．都没能回家陪女朋友
     */
    if(*header == NULL) {
        printf("cannot free_http_header: do not double free http_header\n");
        return;
    }
    struct list_head *head = &((*header)->head);
    struct list_head *pos =  head->next;
    struct list_head *tmp = NULL;
    while(pos != head) {
        tmp = pos->next;
        http_field_t *field = list_entry(pos, http_field_t, list);
        SAFE_FREE(field);
        pos = tmp;
    }
    SAFE_FREE(*header);
}


int hex2dec(char *hex, unsigned int *dec)
{
#ifdef FUNC
    printf("==========start hex2dec()==========\n");
#endif
    int i = 0;
    int power;
    int max_power = strlen(hex);
    *dec = 0;
    for(i = 0; i < max_power; i++)
    {
        int truth;
#ifdef DEBUG_HTTP
        printf("hex[%d]=%c\n", i, hex[i]);
#endif
        if(hex[i] >= '0' && hex[i] <= '9')
            truth = hex[i] - '0';
        else if(hex[i] >= 'a' && hex[i] <= 'f')
            truth = hex[i] - 'a' + 10;
        else if(hex[i] >= 'A' && hex[i] <= 'F')
            truth = hex[i] - 'A' + 10;
        else
            return -1;
        power = max_power - i - 1;
#ifdef DEBUG_HTTP
        printf("truth=%d, power=%d\n", truth, power);
#endif
        *dec += (unsigned int)(truth * pow(16, power));
    }
#ifdef FUNC
    printf("==========finish hex2dec()==========\n");
#endif
    return 0;
}

int erase_nhex(char *chunk_size)
{
#ifdef FUNC
    printf("==========start erase_nhex()==========\n");
#endif
    int len = strlen(chunk_size);
    int i = 0;

    for(i = 0; i < len; i++)
        if(!(((chunk_size[i] >= '0' && chunk_size[i] <= '9')) || (chunk_size[i] >= 'a' && chunk_size[i] <= 'f')))
            chunk_size[i] = '\0';
#ifdef FUNC
    printf("==========finish erase_nhex()==========\n");
#endif
    return 0;
}


/* get_pr_encd()
 * return : content-length
 */
int get_pr_encd(struct list_head *head, int *pr, int *encd)
{
#ifdef FUNC
    printf("==========start get_pr_encd()==========\n");
#endif
    int len = 0;
    int is_txt = 0;
    int is_clen = 0;
    int is_chunk = 0;
    struct list_head *pos = NULL;
    *pr = PR_NONE;
    *encd = ENCD_NONE;
    list_for_each(pos, head){
        http_field_t *field = list_entry(pos, http_field_t, list);

        /* openwrt 使用的是ulibc，包含strcasestr函数, glibc也包含 */
        if (strcasestr(field->key, "Content-type")) {
#ifdef DEBUG_HTTP
            printf("\033[32m");
            printf("[%s%s]\n", field->key, field->value);
            printf("\033[0m");
#endif
            c_type_t *t;
            for (t = text_table; t->type; t++) {
                if (strcasestr(field->value, t->type)) {
                    is_txt = 1;
                    break;
                }
            }
        }

        if (strcasestr(field->key, "Content-length")) {
#ifdef DEBUG_HTTP
            printf("\033[32m");
            printf("[%s%s]\n", field->key, field->value);
            printf("\033[0m");
#endif
            is_clen = 1;
            len = (int) atoi(field->value);
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
                *encd = ENCD_GZIP;
            }
            /*
             * not used
             else if(strcasestr(field->value, "br")) {
             *encd = ENCD_BR;
             }
             else if(strcasestr(field->value, "deflate")) {
             *encd = ENCD_DEFLATE;
             }
             else if(strcasestr(field->value, "compress")) {
             *encd = ENCD_COMPRESS;
             }
             */
            else {
                *encd = ENCD_NONE;
            }
        }
    }

#ifdef DEBUG_HTTP
    printf("is_txt=%d\n", is_txt);
#endif
    *pr = is_chunk?PR_CHUNK:(is_clen?PR_LEN:PR_NONE);
    
    /*
    if(is_txt) {
        *pr = is_chunk?PR_TXT_CHUNK:(is_clen?PR_TXT_LEN:PR_TXT_NONE);
    }
    else {
        *pr = is_chunk?PR_NONE_TXT_CHK:(is_clen?PR_NONE_TXT_LEN:PR_NONE_TXT_NONE);
    }
    */
#ifdef FUNC
    printf("==========finish get_pr_encd()==========\n");
#endif
    return len;
}


/* return:
 *  -1 : 没有找到host字段
 *  0  : ok 
 */
int get_host_port(http_header_t *header, char *host, short *port)
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
                    *port = (short) atoi(s_port);  //aoti(" 123 ") also works well
                }
                else if(ret == 1) {
                    syslog(LOG_INFO, "get_host_port [%s] sscanf only return 1, make port default 80/443", start);
                    *port = (proxy==HTTPS)?DEFAULT_HTTPS_PORT:DEFAULT_HTTP_PORT;
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
                *port = (proxy==HTTPS)?DEFAULT_HTTPS_PORT:DEFAULT_HTTP_PORT;
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
        sprintf(buff, "%s %s %s", header->method, header->url, header->ver);
    }
    else if(req_rsp == IS_RESPONSE) {
        sprintf(buff, "%s %s %s", header->ver, header->stat_code, header->stat_info);
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
        strcat(buff, field->value);
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
int rewrite_clen_encd(struct list_head *head, int content_length, int gunzip)
{
#ifdef FUNC
    printf("==========start rewrite_clen_encd()==========\n");
#endif
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
            }
        }
        pos = pos->next;
    }
#ifdef FUNC
    printf("==========finish rewrite_clen_encd()==========\n");
#endif
    return 0;
}

int rewrite_encd(struct list_head *head, int encd)
{
#ifdef FUNC
    printf("==========start rewrite_c_encd()==========\n");
#endif
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


struct list_head *read_all_chunk(int fd, SSL *ssl)
{
#ifdef FUNC
    printf("==========start read_all_chunk()==========\n");
#endif
    struct list_head *head = (struct list_head *)calloc(1, sizeof(struct list_head));
    init_list_head(head);
    while(1) {
        http_chunk_t *chunk = (http_chunk_t *)calloc(1, sizeof(http_chunk_t));
        if(NULL == chunk) {
            free_chunk_list(head);
            SAFE_FREE(head);
            return head;
        }
        if(read_parse_chunk(fd, ssl, chunk) <= 0) {
            free_chunk_list(head);
            SAFE_FREE(head);
            return head;
        }
        list_add_tail(&(chunk->list), head);
        if(chunk->chk_size <= 0) {
            break;
        }
    }
#ifdef FUNC
    printf("==========finish read_all_chunk()==========\n");
#endif
    return head;
}


/*
 * 读取一个chunk并
 * return:  ok    : 1  
 *          failed: <=0
 */ 
int read_parse_chunk(int fd, SSL* ssl, http_chunk_t *chunk)
{
    int ret;
    ret = read_parse_chk_size_ext_crlf(fd, ssl, chunk);
    if(ret <= 0) {
        return ret;
    }
    return read_parse_chk_body_crlf(fd, ssl, chunk);
}

int read_parse_chk_size_ext_crlf(int fd, SSL* ssl, http_chunk_t *chunk)
{
    int ret;
    char line[LEN_LINE] = {0};
    ret = read_line(fd, ssl, line, sizeof(line));
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


int read_parse_chk_body_crlf(int fd, SSL *ssl, http_chunk_t *chunk)
{
    /* 非trailer */
    /* 可能是压缩过的内容:w */
    if(chunk->chk_size > 0) {
        int ret1, ret2;
        chunk->trl_size = 0;
        chunk->body = (char *)calloc(1, chunk->chk_size);
        ret1 = readn(fd, ssl, chunk->body, chunk->chk_size);
        if(ret1 <=0) {
            printf("readn in read_parse_chk_body_crlf return %d\n", ret1);
            return ret1;
        }
        if(ret1 != chunk->chk_size) {
            printf("chunk body: should read %d, actual read %d\n", chunk->chk_size, ret1);
        }
        ret2 = read_line(fd, ssl, chunk->body_crlf, sizeof(chunk->body_crlf));
        if(ret2 <=0) {
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
        while((ret = read_line(fd, ssl, line, sizeof(line))) > 0){
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

int is_empty_line(const char *line)
{
    if(NULL == line) {
        return 0;
    }
    int len = strlen(line);
    if(1 == len && line[0] == '\n'){
        return 1;
    }
    else if(2 == len && line[0] == '\r' && line[1] == '\n') {
        return 1;
    }
    else {
        return 0;
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

int print_ssl_error(SSL *ssl, int ret, const char *remark)
{
    switch(SSL_get_error(ssl, ret)) {
        case SSL_ERROR_NONE:
            printf("%s : ret = %d, ssl_error_none\n", remark, ret);
            return 0;
        case SSL_ERROR_ZERO_RETURN:
            printf("%s : ret = %d, ssl_error_zero_return\n", remark, ret);
            break;
        case SSL_ERROR_WANT_READ:
            printf("%s : ret = %d, ssl_error_want_read\n", remark, ret);
            break;
        case SSL_ERROR_WANT_WRITE:
            printf("%s : ret = %d, ssl_error_want_write\n", remark, ret);
            break;
        case SSL_ERROR_WANT_CONNECT:
            printf("%s : ret = %d, ssl_error_want_connect\n", remark, ret);
            break;
        case SSL_ERROR_WANT_ACCEPT:
            printf("%s : ret = %d, ssl_error_want_accept\n", remark, ret);
            break;
        case SSL_ERROR_WANT_X509_LOOKUP:
            printf("%s : ret = %d, ssl_error_want_x509_lookup\n", remark, ret);
            break;
            /*
               case SSL_ERROR_WANT_ASYNC:
               printf("ssl_error_want_async\n");
               break;
               case SSL_ERROR_WANT_ASYNC_JOB:
               printf("ssl_error_want_async_job\n");
               break;
               case SSL_ERROR_WANT_CLIENT_HELLO_CB:
               printf("ssl_error_want_client_hello_cb\n");
               break;
               */
        case SSL_ERROR_SYSCALL:
            printf("%s : ret = %d, ssl_error_syscall\n", remark, ret);
            perror("ssl_error_syscall");
            break;
        case SSL_ERROR_SSL:
            printf("%s : ret = %d, ssl_error_ssl\n", remark, ret);
            break;
        default:
            printf("%s : ret = %d, ssl_error_unknown\n", remark, ret);
            break;
    }
    return -1;
}

SSL_SESSION *get_ssl_session(struct list_head *head, const char *ip)
{
    struct list_head *pos;
    list_for_each(pos, head) {
        proxy_sess_t *sess = list_entry(pos, proxy_sess_t, list);
        if(strcmp(sess->ip, ip) == 0) {
            return sess->session;
        }
    }
    return NULL;
}

int set_ssl_sesstion(struct list_head *head, const char *ip, SSL_SESSION *session)
{
    struct list_head *pos;
    list_for_each(pos, head) {
        proxy_sess_t *sess = list_entry(pos, proxy_sess_t, list);
        if(strcmp(sess->ip, ip) == 0) {
            pthread_mutex_lock(&(sess->lock));
            if(sess->session) {
                printf("sess->session exist %p\n", sess->session);
                SSL_SESSION_free(sess->session);
                printf("after SSL_SESSION_free sess->session=%p\n", sess->session);
            }
            sess->session = SSL_SESSION_dup(session);
            pthread_mutex_unlock(&(sess->lock));

            if(sess->session) {
                printf("set_ssl_session ok\n");
                return 0;
            }
            else {
                printf("set_ssl_session failed\n");
                return -1;
            }
        }
    }
    proxy_sess_t *sess = (proxy_sess_t *)calloc(1, sizeof(proxy_sess_t));
    strcpy(sess->ip, ip);
    pthread_mutex_init(&(sess->lock), NULL);
    list_add_tail(head, &(sess->list));
    sess->session = SSL_SESSION_dup(session);
    if(sess->session) {
        printf("set_ssl_session ok, add new\n");
        return 0;
    }
    else {
        printf("set_ssl_session failed, add new\n");
        return -1;
    }
}
