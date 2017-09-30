#define PCRE2_CODE_UNIT_WIDTH 8
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <fcntl.h>
#include <pcre2.h>
#include <signal.h>
#include <syslog.h>
#include <math.h>
#include "list.h"
#include "safe_free.h"
#include "str_replace.h"
#include "err_quit.h"
#include "pad_rplstr.h"
#include "http_rpl.h"

//watch out SIG_PIPE
//SIGPIPE默认导致进程退出.如果对端关闭了连接,那么子进程就没有存在的意义了.直接退出更好.
extern int h_errno;
int l_fd;
int c_fd;
short l_port;
pcre2_code *re;
struct list_head *remap_table;

void replace_field(char *field_value, int direction);
int remap_http_header(struct list_head *head, int direction);
void wait_child(int signo);
int create_proxy_server(short l_port);
int handle_client();
int create_real_server(const char *host, short s_port);
void forward_c2s(int c_fd, int s_fd, http_request_t *req_header);
void forward_s2c(int s_fd, int c_fd, int in_remap_table);
void forward_http_header(int fd, void *http_header, int from);
void forward_http_body(int fd, char *body, int len);
void free_http_header(void *http_header, int from);
PCRE2_SPTR replace_content_default_m(char *old);
int forward_http_chunked(int s_fd, int c_fd);
int dec2hex(unsigned int dec, char *hex);
int hex2dec(char *hex, unsigned int *dec);
int erase_ndigit(char *chunk_size);
int rewrite_content_length(struct list_head *head, int content_length);
void rewrite_url(http_request_t *req);
int proxy_listen(void);
//char *get_pattern_m(const char *path);

//效率太低，后面再改
void replace_field(char *field_value, int direction)
{
#ifdef DEBUG
    //printf("before replace value=%s\n", field_value);
#endif
    PCRE2_SPTR subject = (PCRE2_SPTR)field_value;
    struct list_head *head = get_list_substring_compiled_code(subject, re);
    if(head == NULL)
        return;
    if(direction == REQUEST)
        pad_list_rplstr_malloc(head, pad_list_rplstr_remap_table_req_m, remap_table);
    else
        pad_list_rplstr_malloc(head, pad_list_rplstr_remap_table_rsp_m, remap_table);
    uint32_t new_size;
    PCRE2_SPTR new_subject = replace_all_default_malloc(subject, head/*, &new_size*/);
    if(NULL == new_subject)
    {
        free_list_substring(&head);
        return;
    }
    memset(field_value, 0, LEN_FIELD_VLAUE);
    strcpy(field_value, (char *)new_subject);
#ifdef DEBUG
    //printf("after replace value=%s\n", field_value);
#endif
    free_list_substring(&head);
    SAFE_FREE(new_subject);
}

int remap_http_header(struct list_head *head, int direction)
{
    /* 使用get方法时 GET /setup.cgi?ip=192.168.1.1&port=8080
     * 这里的ip作为客户提交的数据不应该被替换 */
    struct list_head *pos = NULL;
    list_for_each(pos, head)
    {

        http_field_t *field = list_entry(pos,http_field_t, list);
        if(strcasecmp(field->key, "Host") == 0)
        {
            //replace ip;效率太低，后面再改
#ifdef DEBUG
            //printf("%s\n", field->key);
#endif
            replace_field(field->value, direction);
        }
        if(strcasecmp(field->key, "Referer") == 0)
        {
            //replace ip
#ifdef DEBUG
            //printf("%s\n", field->key);
#endif
            replace_field(field->value, direction);
        }
        //if暂时就知道这两个字段要修改
    }
    return 0;
}

void wait_child(int signo)
{
    if(signo == SIGCHLD)
    {
        pid_t pid;
        while((pid = wait(NULL)) > 0)
            printf("wait %d\n", pid);
    }
    else if(signo == SIGPIPE)
        printf("capture SIGPIPE\n");
    else
        printf("capture SIG_%d\n", signo);
}


int create_proxy_server(short l_port)
{
    int l_fd = socket(AF_INET, SOCK_STREAM,  0);
    if(l_fd < 0)
        err_quit("socket");
    int opt = 1;
    setsockopt(l_fd,  SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));

    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(l_port);
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    /* inet_pton(AF_INET, "192.168.1.102", &local_addr.sin_addr.sin_addr); */
    if(bind(l_fd, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0)
        err_quit("bind");
    if(listen(l_fd, 100) < 0)
        err_quit("listen");
    return l_fd;
}

int handle_client()
{
    /*
     * 接收请求头
     * remap请求头
     * 创建到服务器的连接s_fd
     * 新建两个子进程
     */

    http_request_t req_header;
    init_list_head(&(req_header.head));
    int ret;
    if((ret = parse_http_request_header(c_fd, &req_header)) < 0)
        exit(0);
    rewrite_url(&req_header);
    remap_http_header(&(req_header.head), REQUEST);

    char  host[256] = {0};
    short s_port;
    if(get_server_host_port(&(req_header.head), host, &s_port) < 0)
        err_quit("get_server_ip_port, IGNORE ERROR MESSAGE");


    int in_remap_table = 0;
    /*
    struct list_head *pos = NULL;
    list_for_each(pos, remap_table)
    {
        remap_entry_t *entry = list_entry(pos, remap_entry_t, list);
        if(strstr(host, entry->before) || strstr(host, entry->after))
        {
            in_remap_table = 1;
            break;
        }
    }
    */
    int s_fd = create_real_server(host, s_port);   /* return means success.*/
    pid_t pid_1 = fork();
    if(pid_1 == 0)
    {
#ifdef DEBUG
        //printf("father_%d deliver c2s_%d\n", getppid(), getpid());
#endif
        forward_c2s(c_fd, s_fd, &req_header);
        shutdown(c_fd, SHUT_RD);
        shutdown(s_fd, SHUT_WR);    /* 半关闭 */
        close(c_fd);
        close(s_fd);
        exit(0);
    }

    pid_t pid_2 = fork();
    if(pid_2 == 0)
    {
#ifdef DEBUG
        //printf("father_%d deliver s2c_%d\n", getppid(), getpid());
#endif
        forward_s2c(s_fd, c_fd, in_remap_table);
        shutdown(s_fd, SHUT_RDWR);
        shutdown(c_fd, SHUT_RDWR);   /* 半关闭 */
        //shutdown(s_fd, SHUT_RD);
        //shutdown(c_fd, SHUT_WR);   /* 半关闭 */
        close(c_fd);
        close(s_fd);
        exit(0);
    }
    close(c_fd);
    close(s_fd);  /* 两个子进程已经得到了s_fd的副本.这里需要关闭一下,其实不关闭应该应可以。waitpid后系统自动回收 */
    return 0;
}

int create_real_server(const char *host, short s_port)
{
    /* 建立和服务器的连接 */
#ifdef DEBUG
    //printf("create_real_server host=%s, port=%d\n", host, s_port);
#endif
    int s_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(s_fd < 0)
        err_quit("socket");
    struct sockaddr_in server_addr;
    struct hostent *server;
    if((server = gethostbyname(host)) == NULL)
    {
        printf("\033[31m");
        printf("gethostbyname %s error, h_error=%d, %s\n", host, h_errno, hstrerror(h_errno));
        printf("\033[0m");
        exit(1);
    }
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(s_port);
    //inet_pton(AF_INET, host, &(server_addr.sin_addr.s_addr));
    memcpy(&(server_addr.sin_addr.s_addr), server->h_addr, server->h_length);
    char ip[LEN_IP] = {0};
#ifdef DEBUG
    //printf("%s <--> %s port=%d\n", host, inet_ntop(AF_INET, server->h_addr, ip, sizeof(ip)), s_port);
#endif
    if(connect(s_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        err_quit("connect");

    return s_fd;
}

/* 过滤使用pattern，最好不要使用全局变量，不然函数不可重入 */
void forward_c2s(int c_fd, int s_fd, http_request_t *req_header)
{
    /* 作用：
     *      转发remap和rewrite后的req_header
     *      过滤,转发body
     */
    forward_http_header(s_fd, req_header, REQUEST);
    free_http_header(req_header, REQUEST);

    //过滤转发body(过滤***未完成***,POST没有长度限制)
    //body要不要转发?如果是post数据,应该是不可以转发的,这是客户端提交的数据
#ifdef DEBUG
    //printf("next: forward body\n");
#endif
    char body_buf[LEN_BODY] = {0};
    int n, m;
    while((n = read(c_fd, body_buf, LEN_BODY)) > 0)
    {
        m = write(s_fd, body_buf, n);
        //m = write(1, body_buf, n);
    }
    return;
}


/* 过滤使用pattern，最好不要使用全局变量，不然函数不可重入 */
void forward_s2c(int s_fd, int c_fd, int in_remap_table)
{
    /* 作用:
     *      接收rsp_header
     *      remap rsp_header
     *      get_priority()
     *      转发过滤后的rsp_header
     *      根据priority过滤转发body
     */
    http_response_t rsp_header;
    init_list_head(&(rsp_header.head));
    int ret;
    if((ret = parse_http_response_header(s_fd, &rsp_header)) < 0)
        return;
    remap_http_header(&(rsp_header.head), RESPONSE);
    int pr = PR_NONE;
    ssize_t content_len;
    if(in_remap_table)
        content_len = get_response_priority(&(rsp_header.head), &pr);

    #ifdef DEBUG
    //printf("pr=%d, content-length=%d\n", pr, content_len);
    #endif


    /* 根据优先级转发 */
    switch(pr)
    {
        case PR_CONTENT_LEN:  /* 嵌套太多,不合适 */
            {
                if(content_len > 0)
                {
                    char *buf_body = (char *)malloc(content_len + 1);
                    if(NULL == buf_body)
                        err_quit("malloc buf_body");
                    memset(buf_body, 0, content_len + 1);
                    int n = 0;
                    if(( n = readn(s_fd, buf_body, content_len)) > 0)
                    {
#ifdef DEBUG
                        printf("actual read %d \n", n);
                       //printf("body\n%s\n", buf_body);     /*** 千万不可对body等使用strlen(),非ASCLL字符串都不要使用strlen() ***/
#endif
                        uint32_t new_size = 0;
                        PCRE2_SPTR new_body = replace_content_default_m(buf_body);
                        if(NULL == new_body)
                        {
                            forward_http_header(c_fd, &rsp_header, RESPONSE);
                            //printf("gonna forward body to client\n");
                            //printf("%s", buf_body);
                            //forward_http_body(c_fd, buf_body, strlen(buf_body));
                            forward_http_body(c_fd, buf_body, n);
                            //printf("finish forward body to client\n");
                            SAFE_FREE(buf_body);
                        }
                        else
                        {
                            rewrite_content_length(&(rsp_header.head), new_size);
                            forward_http_header(c_fd, &rsp_header, RESPONSE);
                            //printf("gonna forward body to client\n");
                            forward_http_body(c_fd, (char *)new_body, new_size);
                            //printf("finish forward body to client\n");
                            SAFE_FREE(buf_body);
                            SAFE_FREE(new_body);
                        }
                    }
                }
                else
                    forward_http_header(c_fd, &rsp_header, RESPONSE); 
                break;
            }
        case PR_CHUNKED:
            {
                forward_http_header(c_fd, &rsp_header, RESPONSE);
                forward_http_chunked(s_fd, c_fd);
                break;
            }
        case PR_NONE_TXT:
        case PR_NONE:
        default:
            {
                forward_http_header(c_fd, &rsp_header, RESPONSE);
                char buf_body[LEN_BODY] = {0};
                int n, m;
                while((n = read(s_fd, buf_body, LEN_BODY)) > 0)
                {
                    m = write(c_fd, buf_body, n);
                    memset(buf_body, 0, LEN_BODY);
                }
                break;
            }
    }
    free_http_header(&rsp_header, RESPONSE);
    return;
}

void forward_http_header(int fd, void *http_header, int from)
{
    int n;
    char buf_line[LEN_LINE] = {0};
    struct list_head *pos = NULL;
    switch(from)
    {
        case RESPONSE:
            {
                http_response_t *header = (http_response_t *)http_header;
                sprintf(buf_line, "%s %s %s\r\n", header->ver, header->stat_code, header->stat_info);
                #ifdef DEBUG
                //printf("%s", buf_line);
                #endif
                if((n = write(fd, buf_line, strlen(buf_line))) <= 0)
                {
                    printf("forward_http_header rsp line err\n");
                    return;
                }
                list_for_each(pos, &(header->head))
                {
                    char buf_field[LEN_LINE] = {0};
                    http_field_t *field = list_entry(pos, http_field_t, list);
                    sprintf(buf_field, "%s: %s\r\n", field->key, field->value);
                    #ifdef DEBUG
                    //printf("%s", buf_field);
                    #endif
                    if((n = write(fd, buf_field, strlen(buf_field))) < 0)
                    {
                        printf("forward_http_header rsp field\n");
                        return;
                    }
                }
                break;
            }
        case REQUEST:
            {
                http_request_t *header = (http_request_t *)http_header;
                sprintf(buf_line, "%s %s %s\r\n", header->method, header->url, header->ver);
                #ifdef DEBUG
                //printf("%s", buf_line);
                #endif
                if((n = write(fd, buf_line, strlen(buf_line))) <= 0)
                {
                    printf("forward_http_header req line err\n");
                    return;
                }
                list_for_each(pos, &(header->head))
                {
                    char buf_field[LEN_LINE] = {0};
                    http_field_t *field = list_entry(pos, http_field_t, list);
                    sprintf(buf_field, "%s: %s\r\n", field->key, field->value);
                    #ifdef DEBUG
                    //printf("%s", buf_field);
                    #endif
                    if((n = write(fd, buf_field, strlen(buf_field))) < 0)
                    {
                        printf("forward_http_header rsp field\n");
                        return;
                    }
                }
                break;
            }
        default:
            return;
    }
    char middle_end[] = "\r\n";
    n = write(fd, middle_end, strlen(middle_end));
    #ifdef DEBUG
    //printf("%s", middle_end);
    #endif
}

void forward_http_body(int fd, char *body, int len)
{
    int n = write(fd, body, len);
    if(n < 0)
        perror("forward_http_body write");
    else if(n != len)
        printf("forward_http_body write body incomplete\n");
}

void free_http_header(void *http_header, int from)
{
    switch(from)
    {
        case REQUEST:  
            {
                http_request_t *header = (http_request_t *)http_header;
                struct list_head *pos = (header->head).next;
                while(pos != &(header->head))
                {
                    struct list_head *temp = pos->next;
                    http_field_t *field = list_entry(pos, http_field_t, list);
                    SAFE_FREE(field);
                    pos = temp;
                }
                break;
            }
        case RESPONSE: 
            {
                http_response_t *header = (http_response_t *)http_header; 
                struct list_head *pos = (header->head).next;
                while(pos != &(header->head))
                {
                    struct list_head *temp = pos->next;
                    http_field_t *field = list_entry(pos, http_field_t, list);
                    SAFE_FREE(field);
                    pos = temp;
                }
                break;
            }
        default:
            exit(0);  /* 通过退出进程的方式隐式回收 */
    }
}


PCRE2_SPTR replace_content_default_m(char *old)
{
    PCRE2_SPTR new;
    struct list_head *head = get_list_substring_compiled_code((PCRE2_SPTR)old, re);
    if(head == NULL)
        return NULL;
    pad_list_rplstr_malloc(head, pad_list_rplstr_remap_table_rsp_m, remap_table);
    uint32_t new_size;
    new = replace_all_default_malloc((PCRE2_SPTR)old, head/*, &new_size*/);
    if(NULL == new)
    {
        free_list_substring(&head);
        return NULL;
    }
    free_list_substring(&head);
    return new;
}

int forward_http_chunked(int s_fd, int c_fd)
{
    char s_size[64] = {0};
    uint32_t size = 0;
    uint32_t n, m;
    char buff[LEN_BODY] = {0};
    char *ptr = buff;
    int tot_buf = 0;
    int left = sizeof(buff);
    int read_size = 1;
    while(1)            /* this while loop if for transfer chunk_size and chunk_data */
    {
        if(read_size)
        {
            if((n = read_line(s_fd, s_size, sizeof(s_size))) <= 0)
                break;
            /* 25\r\n */
            if(strcmp(s_size, "0\r\n") == 0)
                break;
            erase_ndigit(s_size);
            /* 25  */
            hex2dec(s_size, &size);
            size += 2;  /* chunk_data + "\r\n" */
        }
        if(size <= left && size > 0)
        {
            if((n = readn(s_fd, ptr, size)) == size)
            {
                ptr += size;
                left -= size;
                read_size = 1;  /* 读完chunked正文后,肯定要读取一下chunked的size */
            }
            else
            {
                size -= n;
                ptr += size;
                left -= size;
            }
        }
        else
        {
            /* 替换转发 */
            char chunk_size[64] = {0};
            read_size = 0;
            PCRE2_SPTR new_chunked = replace_content_default_m(buff);
            if(NULL == new_chunked)
            {
                sprintf(chunk_size, "%x\r\n", LEN_BODY - left);
                m = write(c_fd, chunk_size, strlen(chunk_size));
                m = write(c_fd, buff, LEN_BODY - left);
            }
            else
            {
                sprintf(chunk_size, "%x\r\n", strlen((char *)new_chunked));
                m = write(c_fd, chunk_size, strlen(chunk_size));
                m = write(c_fd, (char *)new_chunked, strlen((char *)new_chunked));
                SAFE_FREE(new_chunked);
            }
            memset(buff, 0, sizeof(buff));
            left = sizeof(buff);
            ptr = buff;
        }
    }


    while((n = read(s_fd, buff, sizeof(buff))) > 0)    /* this while loop is for chunk 拖挂内容 */
    {
        m = write(c_fd, buff, c_fd);
    }
    return 0;
}


int dec2hex(unsigned int dec, char *hex)
{
    return sprintf(hex, "%x", dec);
}


int hex2dec(char *hex, unsigned int *dec)
{
    int i = 0;
    *dec  = 0;
    int power;
    int max_power = strlen(hex);
    for(i = 0; i < max_power; i++)
    {
        int truth;
#ifdef DEBUG
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
#ifdef DEBUG
        printf("truth=%d, power=%d\n", truth, power);
#endif
        *dec += (unsigned int)(truth*pow(16, power));
    }
    return 0;
}

int erase_ndigit(char *chunk_size)
{
    int len = strlen(chunk_size);
    int i = 0;
    for(i = 0; i < len; i++)
    {
        if(!(chunk_size[i] >= '0' && chunk_size[i] <= '9'))
            chunk_size[i] = ' ';
    }
    return 0;
}

/* return:
 * 0: not rewrite
 * 1: rewrite
 */
int rewrite_content_length(struct list_head *head, int content_length)
{
    struct list_head *pos;
    list_for_each(pos, head)
    {
        http_field_t *field = list_entry(pos, http_field_t, list);
        if(strcasecmp("Content-length", field->key))
        {
            memset(field->value, 0, LEN_FIELD_VLAUE);
            return sprintf(field->value, "%d", content_length);
        }
    }
    return 0;
}

void rewrite_url(http_request_t *req)
{
    /* 转换url到 path */
    char *p = strstr(req->url,"http://");
    if(p)
    {
        char *p1 = strchr(p + 7,'/');
        if(p1) 
        {
            /* http://192.168.1.33/setup.cgi?nextfile=remap.html  --> /setup.cgi?nextfile=remap.html */
            int end = strlen(p1);
            memmove(req->url, p1, strlen(p1));
            *(req->url + end) = '\0';
        }
        else
        {
            /* http://192.168.1.33 --> / */
            memset(req->url, 0, LEN_URL);
            strcpy(req->url, "/");
        }
    }
#ifdef DEBUG
    //printf("after rewrite url=%s\n", req->url);
#endif
}

/*
   char *get_pattern_m(const char *path)
   {
   int fd = open(path, O_RDONLY);
   if(fd < 0)
   {
   perror("open pattern_file");
   return NULL;
   }
   struct stat buffer;
   if(0 != stat(path, &buffer))
   return NULL;
   if(buffer.st_size == 0)
   {
   printf("nothing to read in %s", path);
   return NULL;
   }
   char *pattern = (char *)malloc(buffer.st_size);
   if(NULL == pattern)
   return NULL;
   int n;
reread:
n = read(fd, pattern, buffer.st_size);
if(n < 0)
{
if(errno == EINTR)
goto reread;
else
{
perror("read");
SAFE_FREE(pattern);
return NULL;
}
}
else if(n != buffer.st_size)
{
printf("read pattern no enough\n");
SAFE_FREE(pattern);
return NULL;
}
return pattern;
}
*/

int main(int argc, char **argv)
{
    if(argc != 2)
    {
        printf("Usage: %s port\n", argv[0]);
        return 0;
    }

    /* 创建监听套接字 */
    l_port = (short)atoi(argv[1]);
    l_fd   = create_proxy_server(l_port);


    /* 注册信号处理函数 */
    if(signal(SIGCHLD, wait_child) == SIG_ERR)
        err_quit("signal");

    /* 获取pattern并编译 */
    /*
    char *pattern = (char *)malloc(LEN_PATTERN);
    if(NULL == pattern)
        err_quit("malloc pattern");
    get_pattern(pattern);
    */
    char pattern[] = "123456";

    if(strlen(pattern) == 0)
    {
        //syslog(LOG_INFO, "[CONFIG] 正则表达式表为空或启用的条目无正则，未启动http_proxy_regex进程");
        printf("正则表达式为空或启用的条目无正则，未启动http_proxy_regex进程\n");
        exit(1);
    }

#ifdef DEBUG
    //printf("pattern=%s\n", pattern);
#endif

    re = get_compile_code((PCRE2_SPTR)pattern, 0);
    if(NULL == re)
        err_quit("pcre2 pattern init failed, IGNORE ERROR MSG");
    //SAFE_FREE(pattern);

    //printf("d\n");
    /* 获取remap_table */
    /*
    remap_table = get_remap_table_m();
    if(NULL == remap_table)
        err_quit("get_remap_table_m failed, IGNORE ERROR MSG");
    */
    remap_table = (struct list_head *)malloc(sizeof(struct list_head));
    if(NULL == remap_table)
        err_quit("malloc remap_table");
    init_list_head(remap_table);
    remap_entry_t *entry = (remap_entry_t *)malloc(sizeof(remap_entry_t));
    if(NULL == entry)
        err_quit("malloc remap_entry");
    memset(entry->before, 0 , LEN_IP);
    memset(entry->after,  0 , LEN_IP);
    strcpy(entry->before, "192.168.1.1");
    strcpy(entry->after, "172.16.5.3");
    entry->direction = 1;
    list_add_tail(&(entry->list), remap_table);
    if(fork() == 0)
    {
        proxy_listen();
    }

    return 0;
}

int proxy_listen(void)
{
    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    socklen_t s_len = sizeof(client_addr);
    char c_ip[LEN_IP] = {0};
    while(1)
    {
        /* 父进程只做监听 */
        c_fd = accept(l_fd, (struct sockaddr *)&client_addr, &s_len);
        printf("cfd=%d, client online :%s, %d\n",
                c_fd, 
                inet_ntop(AF_INET, &client_addr.sin_addr.s_addr, c_ip, sizeof(c_ip)), 
                ntohs(client_addr.sin_port));
        pid_t pid = fork();
        if(pid < 0)
            perror("father fork");
        else if(pid == 0)
        {
            close(l_fd);
#ifdef DEBUG
            //printf("father_%d deliver child_%d\n", getppid(), getpid());
#endif
            handle_client();    /* 创建两个子进程，一个转发c->s,一个转发s->c */
            //回收子进程后再退出，如何做？
            exit(0);
        }
        else
            close(c_fd);
    }
}
