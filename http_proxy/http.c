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
    { "application/atom+xml"   },
    { "application/json"       },   /* 南京茂业 */
    { "application/soap+xml"   },   /* 南京茂业 */
    { "application/rdf+xml"    },
    { "application/rss+xml"    },
    { "application/xhtml+xml"  },
    { "application/xml-dtd"    },
    { "application/xop+xml"    },
    { "application/rdf+xml"    },
    { "application/xml"        }  /* 海康枪式摄像头 */
};

static int _readn(int fd, void *buff, int n);
static int _read_line(int fd, char *buff, int cnt);
static int _read_double_crlf(int fd, char *buff, int cnt);
static int _readn_ssl(SSL *ssl, void *buff, int n);
static int _read_line_ssl(SSL *ssl, char *buff, int cnt);
static int _read_double_crlf_ssl(SSL *ssl, char *buff, int cnt);

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

int read_double_crlf(int fd, SSL *ssl, char *buff, int n)
{
    return (proxy == HTTP)?_read_double_crlf(fd, buff, n):_read_double_crlf_ssl(ssl, buff, n);
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
 * read_double_crlf()
 * return : 
 *  -1 : failed
 *  >0 : actual num readed
 */
static int _read_double_crlf(int fd, char *buff, int cnt)
{
#ifdef FUNC
    printf("==========start _read_double_crlf()==========\n");
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
                perror("_read_double_crlf: read()");
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
            printf("0x%02x 0x%02x 0x%02x 0x%02x\n", start[tot_read - 4], start[tot_read - 3], start[tot_read  - 2], start[tot_read - 1]);
#endif
            if('\r' == start[tot_read - 4] &&
                    '\n' == start[tot_read - 3] &&
                    '\r' == start[tot_read - 2] &&
                    '\n' == start[tot_read - 1]) {
                break;
            }
        }
    }
#ifdef TIME_COST
    gettimeofday(&end, NULL);
    printf("execute _read_double_crlf use time: start=%lds %ldms, end in %lds %ldms\n", strt.tv_sec, strt.tv_usec, end.tv_sec, end.tv_usec);
#endif
#ifdef FUNC
    printf("==========finish _read_double_crlf()==========\n");
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
 * read_double_crlf()
 * return : 
 *  -1 : failed
 *  >0 : actual num readed
 */
static int _read_double_crlf_ssl(SSL *ssl, char *buff, int cnt)
{
#ifdef FUNC
    printf("==========start _read_double_crlf_ssl()==========\n");
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
            print_ssl_error(ssl, n, "_read_double_crlf_ssl()");
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
            printf("0x%02x 0x%02x 0x%02x 0x%02x\n", start[tot_read - 4], start[tot_read - 3], start[tot_read  - 2], start[tot_read - 1]);
#endif
            if('\r' == start[tot_read - 4] &&
                    '\n' == start[tot_read - 3] &&
                    '\r' == start[tot_read - 2] &&
                    '\n' == start[tot_read - 1]) {
                break;
            }
        }
    }
#ifdef TIME_COST
    gettimeofday(&end, NULL);
    printf("execute _read_double_crlf_ssl use time: start=%lds %ldms, end in %lds %ldms\n", strt.tv_sec, strt.tv_usec, end.tv_sec, end.tv_usec);
#endif
#ifdef FUNC
    printf("==========finish _read_double_crlf_ssl()==========\n");
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
 */
int parse_http_header(const char *buf, http_header_t *header)
{
#ifdef FUNC
    printf("==========start parse_http_header()==========\n");
#endif
#ifdef DEBUG_HTTP
    printf("parse_http_header:\n[%s]\n", buf);
#endif
    if(buf == NULL) {
        return -1;
    }
    char *line;
    char *start;
    char *crlf;
    start = buf;
    line  = buf;
    int ret;
    /* 请求行/状态行 */
    if(crlf = strstr(line, "\r\n")) {
        *crlf = '\0';
#ifdef DEBUG_HTTP
        printf("%s\n", line);
#endif
        char str[LEN_METHOD + LEN_VER] = {0};
        char mid[LEN_URL + LEN_STAT_CODE] = {0};
        char end[LEN_VER + LEN_STAT_INFO] = {0};
        char *format = "%s %s %[^'\r''\n']";
        ret = sscanf(line, format, str, mid, end);
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
        line = crlf + 2;
    }
    /* field */
    while((crlf = strstr(line, "\r\n"))) {
        *crlf = '\0';
#ifdef DEBUG_HTTP
        printf("%s\n", line);
#endif
        http_field_t *field = (http_field_t *)malloc(sizeof(http_field_t));
        if(parse_http_field(line, field) < 0) {
#ifdef DEBUG_HTTP
            printf("cannot parse_http_line[%s]", line);
#endif
        }
        else {
            list_add_tail(&(field->list), &(header->head)); 
        }
        line = crlf + 2;
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
    //printf("==========start parse_http_field()==========\n");
#endif
    int ret;
    char *p = strchr(line, ':');
    if(NULL == p) {
        return -1;
    }
    *p = '\0';
    strcpy(field->key, line);
    strcpy(field->value, p + 1);
#ifdef FUNC
    //printf("==========finish parse_http_field()==========\n");
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

        if (strcasecmp("Content-type", field->key) == 0) {
#ifdef DEBUG_HTTP
            printf("\033[32m");
            printf("Content-type: %s\n", field->value);
            printf("\033[0m");
#endif
            int i = 0;
            for (i = 0; i < sizeof (text_table) / sizeof (c_type_t); i++) {
                if (strstr(field->value, text_table[i].type)) {
                    is_txt = 1;
                    break;
                }
            }
#ifdef DEBUG_HTTP
            printf("is_txt=%d\n", is_txt);
#endif
        }

        if (strcasecmp("Content-length", field->key) == 0) {
#ifdef DEBUG_HTTP
            printf("\033[32m");
            printf("Content-length: %s\n", field->value);
            printf("\033[0m");
#endif
            is_clen = 1;
            len = (int) atoi(field->value);
        }

        if (strcasecmp("Transfer-encoding", field->key) == 0 && strstr(field->value, "chunked")) {
#ifdef DEBUG_HTTP
            printf("\033[32m");
            printf("Transfer-encoding: %s\n", field->value);
            printf("\033[0m");
#endif
            is_chunk = 1;
        }

        if (strcasecmp("Content-Encoding", field->key) == 0)
        {
#ifdef DEBUG_HTTP
            printf("\033[32m");
            printf("Content-encoding: %s\n", field->value);
            printf("\033[0m");
#endif
            if (strstr(field->value, "gzip")) {
                *encd = ENCD_GZIP;
            }
            else {
                *encd = ENCD_NONE;
            }
        }
    }

    if(is_txt) {
        if(is_chunk) {
            *pr = PR_TXT_CHUNK;
        }
        else if (is_clen) {
            *pr = PR_TXT_LEN;
        }
        else {
            *pr = PR_TXT_NONE;
        }
    }
    else {
        if(is_chunk) {
            *pr = PR_NONE_TXT_CHK;
        }
        else if(is_clen) {
            *pr = PR_NONE_TXT_LEN;
        }
        else {
            *pr = PR_NONE_TXT_NONE;
        }

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

        if (strcasecmp(field->key, "Host") == 0)
        {
            char *space = strchr(field->value, ' ');
            char *colon = strchr(field->value, ':');
            if(NULL == space) {
                space = field->value;
            }
            else {
                space += 1;
            }

            if (colon) {
                char *format = "%[^:]:%s";
                char s_port[12] = { 0 };
                ret = sscanf(space, format, host, s_port);
                if(ret == 2) {
                    *port = (short) atoi(s_port);  //aoti(" 123 ") also works well
                }
                else if(ret == 1) {
                    *port = (proxy==HTTPS)?DEFAULT_HTTPS_PORT:DEFAULT_HTTP_PORT;
                }
                else {
                    return -1;
                }
            }
            else {
                strcpy(host, space);
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
        if(*(header->method) != '\0' &&
           *(header->url) != '\0' &&
           *(header->ver) != '\0') {
            sprintf(buff, "%s %s %s\r\n", header->method, header->url, header->ver);
        }
        else {
            printf("http_header_tostr: request. first line wrong.\n");
            return -1;
        }
    }
    else if(req_rsp == IS_RESPONSE) {
        if(*(header->ver) != '\0' &&
           *(header->stat_code) != '\0' &&
           *(header->stat_info) != '\0') {
            sprintf(buff, "%s %s %s\r\n", header->ver, header->stat_code, header->stat_info);
        }
        else {
            printf("http_header_tostr: response.  first line wrong.\n");
            return -1;
        } 
    }
    else {
        printf("http_header_tostr: neither request or response\n");
        return -1;
    }
    
    struct list_head *head = &(header->head);
    struct list_head *pos = NULL;
    list_for_each(pos, head) {
        http_field_t *field = list_entry(pos, http_field_t, list);
        //printf("%s: %s\n", field->key, field->value);
        sprintf(buff, "%s%s:%s\r\n", buff, field->key, field->value);
    }
    strcat(buff, "\r\n");
#ifdef DEBUG_HTTP
//    if(req_rsp == IS_RESPONSE) {
        printf("\nhttp_header_tostr:\n[%s]\n", buff);
//    }
#endif
#ifdef FUNC
    printf("==========finish http_header_tostr()==========\n");
#endif
#ifdef TIME_COST
    gettimeofday(&end, NULL);
    printf("execute header_to_str use time: start=%lds %ldms, end in %lds %ldms\n", strt.tv_sec, strt.tv_usec, end.tv_sec, end.tv_usec);
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
    struct list_head *pos;
    list_for_each(pos, head){
        http_field_t *field = list_entry(pos, http_field_t, list);

        if(strcasecmp("Content-length", field->key) == 0)
        {
            memset(field->value, 0, LEN_FIELD_VALUE);
            sprintf(field->value, "%d", content_length);
        }
        if(strcasecmp("Content-encoding", field->key) == 0)
        {
            if(gunzip == GZIP2FLATE)
            {
                memset(field->value, 0, LEN_FIELD_VALUE);
                sprintf(field->value, "%s", "none");
            }
        }
    }
#ifdef FUNC
    printf("==========finish rewrite_clen_encd()==========\n");
#endif
    return 0;
}

int rewrite_c_encd(struct list_head *head, int encd)
{
#ifdef FUNC
    printf("==========start rewrite_c_encd()==========\n");
#endif
    struct list_head *pos;
    list_for_each(pos, head)
    {
        http_field_t *field = list_entry(pos, http_field_t, list);
        if(strcasecmp("Content-encoding", field->key) == 0)
        {
            if(encd == ENCD_FLATE)
            {
                memset(field->value, 0, LEN_FIELD_VALUE);
                sprintf(field->value, "%s", " ");
            }
            else if(encd == ENCD_GZIP)
            {
                memset(field->value, 0, LEN_FIELD_VALUE);
                sprintf(field->value, "%s", "gzip");
            }
        }
    }
#ifdef FUNC
    printf("==========finish rewrite_c_encd()==========\n");
#endif
    return 0;
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
