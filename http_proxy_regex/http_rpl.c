#include "http_rpl.h"

c_type_t text_table[] = {
	{"text/h323"},
	{"text/asa"},
	{"text/asp"},
	{"text/xml"},
	{"text/x-component"},
	{"text/html"},
	{"text/javascript"},
	{"text/x-vcard"},
	{"text/scriptlet"},
	{"text/vnd.wap.wml"},
	{"text/iuls"},
	{"text/plain"},
	{"text/vnd.rn-realtext"},
	{"text/vnd.rn-realtext3d"},
	{"text/x-ms-doc"},
	{"text/webviewhtml"},
	{"text/css"}
};
int parse_http_request_header(int c_fd, http_request_t *req)
{
    int n = 0;
    char line[LEN_LINE] = {0};
    if((n = read_line(c_fd, line, sizeof(line))) <= 0)
        return -1;
    #ifdef HTTPDEBUG
    printf("line=%s", line);
    #endif
    parse_http_req_line(line, req);
    memset(line, 0, sizeof(line));
    while((n = read_line(c_fd, line, sizeof(line))) > 0)
    {
        if(strcmp(line, "\r\n") != 0)
        {
            #ifdef HTTPDEBUG
            printf("line=%s", line);
            #endif
            http_field_t *field = (http_field_t *)malloc(sizeof(http_field_t));
            parse_http_filed(line, field);
            list_add_tail(&(field->list), &(req->head));
            memset(line, 0, sizeof(line));
        }
        else
            break;
    }
    return 0;
}

int parse_http_response_header(int s_fd, http_response_t *rsp)
{
    int n = 0;
    char line[LEN_LINE] = {0};
    if((n = read_line(s_fd, line, sizeof(line))) <= 0)
        return -1;
    #ifdef HTTPDEBUG
    printf("line=%s", line);
    #endif
    parse_http_rsp_line(line, rsp);
    memset(line, 0, sizeof(line));
    while((n = read_line(s_fd, line, sizeof(line))) > 0)
    {
        if(strcmp(line, "\r\n") != 0 && strcmp(line, "\n") != 0)
        {
            #ifdef HTTPDEBUG
            printf("line=%s", line);
            #endif
            http_field_t *field = (http_field_t *)malloc(sizeof(http_field_t));
            parse_http_filed(line, field);
            list_add_tail(&(field->list), &(rsp->head));
            memset(line, 0, sizeof(line));
        }
        else
            break;
    }
    return 0;
}

//缺陷版,可以结合readn使用
int read_line(int fd, char *buff, int cnt)
{
    int  tot_read = 0;
    int  n = 0;
    char c = 0;
    while(1)
    {
        n = read(fd, &c, 1);
        if(n < 0)
        {
            if(errno == EINTR)
                continue;
            else
                return -1;
        }
        else if(n == 0)
        {
            break;
        }
        else
        {
            if(tot_read < cnt - 1)
            {
                tot_read++;
                *buff++ = c;
            }
            //一行超过最大缓存长度的部分就被阶段了
            //需要修改
        }
        if(c == '\n')
            break;
    }
    return tot_read;
}

//此函数不可重入
//多线程不安全
//多进程安全
ssize_t my_read(int fd, char *ptr)
{
    /* 第一次调用读取至多100字节存在静态区域
     * 下次调用直接从静态区域中取出一个字节,如此避免了频繁调用read,降低了开销？
     * 调用函数的开销大，还是调用系统函数read的开销大？
     */
    static int read_cnt = 0;
    static char *read_ptr;
    static char read_buf[100];
    if(read_cnt <= 0)
    {
again:
        if((read_cnt = read(fd, read_buf, sizeof(read_buf)))< 0)
        {
            if(errno == EINTR)
                goto again;
        }
        else if(read_cnt == 0)
            return 0;
        read_ptr = read_buf;
    }
    read_cnt--;
    *ptr = *read_ptr++;
    return 1;
}

//不可以结合readn使用
ssize_t read_line2(int fd, void *buff, size_t maxlen)
{
    ssize_t n, rc;
    char c, *ptr;
    ptr = buff;
    for(n = 1; n < maxlen; n++)
    {
        if((rc = my_read(fd, &c)) == 1)
        {
            *ptr++ = c;
            if(c == '\n')
                break;
        }
        else if(rc == 0)
        {
            *ptr = 0;
            return (n - 1);
        }
        else
            return -1;
    }

    *ptr = 0;
    return n;
}



/* return
 *      -1 : err
 *      0  : 读到结尾
 *      >0 : 没有读满
 * 还可能阻塞住
 * 如何处理Content-length与实际情况不符合的情况,是否要使用select超时机制
 */
ssize_t readn(int fd, void *buff, int n)
{
    ssize_t nread;
    size_t  nleft = n;
    char *ptr = buff;
    while(nleft > 0)
    {
        if((nread = read(fd, ptr, nleft)) < 0)
        {
            if(errno == EINTR)
                continue;
            else
            {
                perror("inreadn read");
                break;
            }
        }
        else if(nread == 0)
            break;
        //write(1, ptr, nread);
        nleft -= nread;
        ptr += nread;
    }
    return (n - nleft);
}

//PS:如果先调用read_line2再调用readn有极大的可能性会错。
//错误:一些存放在静态区的数据未被取出.

void parse_http_req_line(const char *line, http_request_t *req_line)
{
    /* get /xxx/yyy/jjdw  HTTP/1.1 */
    char *format = "%s %s %[^'\r''\n']";
    sscanf(line, format, req_line->method, req_line->url, req_line->ver);
}

void parse_http_rsp_line(const char *line, http_response_t *rsp_line)
{
    /* HTTP/1.1 200 OK */
    char *format = "%s %s %[^'\r''\n']";
    sscanf(line, format, rsp_line->ver, rsp_line->stat_code, rsp_line->stat_info);
}


void parse_http_filed(const char *line, http_field_t *field)
{
    /* Host: 192.168.1.33 */
    /* Date: 2017.09.20 11:33:33 */
    char *format = "%[^:]:%*[ ]%[^'\r''\n']";   //'\r'也必须要去除
    sscanf(line, format, field->key, field->value);
}


int get_server_host_port(struct list_head *req_head, char *host, short *s_port)
{
    struct list_head *pos = NULL;
    list_for_each(pos, req_head)
    {
        http_field_t *field = list_entry(pos, http_field_t, list);
        if(strcasecmp(field->key, "Host") == 0)
        {
            char *p1 = strchr(field->value, ':');
            if(p1)
            {
                char *format = "%[^:]:%s";
                char port[12] = {0};
                if(2 == sscanf(field->value, format, host, port))
                    *s_port = (short)atoi(port);   //aoti(" 123 ") also works well
                else 
                    *s_port = DEFAULT_SERVER_PORT;
            }
            else
            {
                strcpy(host, field->value);
                *s_port = DEFAULT_SERVER_PORT;
            }
            return 0;
        }
    }
    return -1;
}

size_t get_response_priority(struct list_head *rsp_head, int *pr)
{
    size_t len = 0;
    int is_txt = 0;
    struct list_head *pos = NULL;
    *pr = PR_NONE;                  /* must initialize *pr as PR_NONE */
    list_for_each(pos, rsp_head)
    {
        http_field_t *field = list_entry(pos, http_field_t, list);
        if(strcasecmp("Content-type", field->key) == 0)
        {
            int i = 0;
            for(i = 0; i < sizeof(text_table)/sizeof(c_type_t); i++)
            {
                if(strstr(field->value, text_table[i].type))
                {
                    is_txt = 1;
                    break;
                }
            }
            if((*pr = is_txt?*pr:PR_NONE_TXT) == PR_NONE_TXT)
                break;
        }
        if(strcasecmp("Content-length", field->key) == 0)
        {
            *pr = (*pr == PR_CHUNKED)?*pr:PR_CONTENT_LEN;
            len = (size_t)atoi(field->value);
        }
        if(strcasecmp("Transfer-encoding", field->key) == 0 && strcasecmp("chunked", field->value))
            *pr = PR_CHUNKED;

    }

    list_for_each(pos, rsp_head)
    {
        http_field_t *field = list_entry(pos, http_field_t, list);
        if(strcasecmp("Content-length", field->key) == 0)
            len = (size_t)atoi(field->value);
    }
    return len;
}

