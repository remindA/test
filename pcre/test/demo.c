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
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <fcntl.h>
#include <pcre2.h>
#include <signal.h>
#include "list.h"
#include "safe_free.h"
#include "str_replace.h"
#include "err_quit.h"
#include "pad_rplstr.h"
#include "http_rpl.h"

//watch out SIG_PIPE
//SIGPIPE默认导致进程退出.如果对端关闭了连接,那么子进程就没有存在的意义了.直接退出更好.
remap_t remap_table[2] = {
    {"192.168.1.33", "172.27.5.33"},
    {"127.0.0.1", "192.168.1.102"}
};

pcre2_code *re;
struct list_head *remap_table;

//效率太低，后面再改
void replace_field_xx(char *field_value)
{
    printf("before replace value=%s\n", field_value);
    PCRE2_SPTR subject = (PCRE2_SPTR)field_value;
    struct list_head *head = get_list_substring_compiled_code(subject, re);
    if(head == NULL)
        return;
    pad_list_rplstr_malloc(head, pad_remap_rplstr_malloc, remap_table, 2);
    PCRE2_SPTR new_subject = replace_all_default_malloc(subject, head);
    if(NULL == new_subject)
    {
        free_list_substring(&head);
        return;
    }
    memset(field_value, 0, LEN_FIELD_VLAUE);
    strcpy(field_value, (char *)new_subject);
    free_list_substring(&head);
    SAFE_FREE(new_subject);
}

int remap_http_header(struct list_head *head)
{
    //使用get方法时 GET /setup.cgi?ip=192.168.1.1&port=8080
    //这里的ip作为客户提交的数据不应该被替换
    struct list_head *pos = NULL;
    list_for_each(pos, head)
    {

        http_field_t *field = list_entry(pos,http_field_t, list);
        if(strcasecmp(field->key, "Host") == 0)
        {
            //replace ip;效率太低，后面再改
            replace_field_xx(field->value);
        }
        if(strcasecmp(field->key, "Referer") == 0)
        {
            //replace ip
            replace_field_xx(field->value);
        }
        //if暂时就知道这两个字段要修改
    }
    return 0;
}

void wait_child(int signo)
{
    while(waitpid(0, NULL, WNOHANG) > 0);
    printf("waitpid\n");
}





int create_proxy_server(short l_port);
{
    int l_fd = socket(AF_INET, SOCK_STREAM,  0);
    if(l_fd < 0)
        err_quit("socket");
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
    remap_http_header(&(req_header.head));

    char  s_ip[LEN_IP] = {0};
    short s_port;
    if(get_server_ip_port(&(req_header.head), s_ip, &s_port) < 0)
        err_quit("get_server_ip_port, IGNORE ERROR MESSAGE");
    int s_fd = create_real_server(s_ip, s_port);   /* return means success.*/

    pid_t pid_1 = fork();
    if(pid_1 == 0)
    {
        forward_c2s(c_fd, s_fd, &req_header);
        shutdown(c_fd, SHUT_RDWR);
        shutdown(s_fd, SHUT_RDWR);
        exit(0);
    }

    pid_t pid_2 = fork();
    if(pid_2 == 0)
    {
        forward_s2c(s_fd, c_fd);
        shutdown(s_fd, SHUT_RDWR);
        shutdown(c_fd, SHUT_RDWR);
        exit(0);
    }
    close(s_fd);  /* 两个子进程已经得到了s_fd的副本.这里需要关闭一下,其实不关闭应该应可以。waitpid后系统自动回收 */
}

int create_real_server(const char *s_ip, short s_port)
{
    /* 建立和服务器的连接 */
    int s_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(s_fd < 0)
        err_quit("socket");
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(s_port);
    inet_pton(AF_INET, s_ip, &(server_addr.sin_addr.s_addr));

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
    char body_buf[LEN_BODY] = {0};
    int n = 0;
    while((n = read(c_fd, body_buf, LEN_BODY)) > 0)
    {
        write(s_fd, body_buf, n);
    }
    return;
}


/* 过滤使用pattern，最好不要使用全局变量，不然函数不可重入 */
void forward_s2c(int s_fd, int c_fd)
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
    remap_http_header(&(rsp_header.head));
    int pr = PR_NONE;
    size_t content_len = get_response_priority(&(rsp_head.head), &pr);


    /* 根据优先级转发 */
    switch(pr)
    {
        case PR_CONTENT_LEN:  /* 嵌套太多,不合适 */
            {
                if(content_len > 0)
                {
                    char *buf_body = (char *)malloc(content_len);
                    memset(buf_body, 0, content_len);
                    int n = 0;
                    if(( n = readn(s_fd, buf_body, content_len)) == content_len)
                    {
                        PCRE2_SPTR new_body = replace_content_default_m(buf_body);
                        if(NULL == new_body)
                        {
                            forward_http_header(c_fd, &rsp_header, RESPONSE);
                            forward_http_body(c_fd, buf_body, strlen(buf_body))
                                free(buf_body);
                        }
                        else
                        {
                            rewite_content_length(&(rsp_header.head), strlen(new_body));
                            forward_http_header(c_fd, &rsp_header, RESPONSE);
                            forward_http_body(c_fd, (char *)new_body, strlen(new_body));
                            free(buf_body);
                            free(new_body);
                        }
                    }
                }
                else
                    forward_http_header(c_fd, &rsp_head, RESPONSE); 
                break;
            }
        case PR_CHUNKED:
            {
                forward_http_header(c_fd, &rsp_head, RESPONSE);
                foward_http_chunked(s_fd, c_fd);
                break;
            }
        case PR_NONE_TXT:
        case PR_NONE:
        default:
            {
                forward_http_header(c_fd, &rsp_head, RESPONSE);
                char buf_body[LEN_BODY] = {0};
                int n = 0;
                while((n = read(s_fd, buf_body, LEN_BODY)) > 0)
                {
                    write(c_fd, buf_body, n);
                    memset(buf_body, 0, LEN_BODY);
                }
                break;
            }
    }
    free_http_header(&rsp_headern RESPONSE);
    return;
}

void forward_http_header(int fd, void *http_header, int from)
{
    int n;
    char buf_line[LEN_LINE] = {0};
    void *header;
    switch(from)
    {
        case RESPONSE:
            {
                header = (http_response_t *)http_header;
                sprintf(buf_line, "%s %s %s\r\n", header->ver, header->stat_code, header->stat_info);
                if((n = write(fd, buf_req_line, strlen(buf_req_line))) <= 0)
                    return;
            }
        case REQUEST:
            {
                header = (http_request_t *)http_header;
                sprintf(buf_line, "%s %s %s\r\n", header->method, header->url, header->ver);
                if((n = write(fd, buf_req_line, strlen(buf_req_line))) <= 0)
                    return;
            }
        default:
            return;
    }

    struct list_head *pos = NULL;
    list_for_each(pos, &(header.head))
    {
        char buf_field[LEN_LINE] = {0};
        http_field_t *field = list_entry(pos, http_field_t, list);
        sprintf(buf_field, "%s: %s\r\n", field->key, field->value);
        if((n = write(fd, buf_field, strlen(buf_field))) < 0)
            return;
    }
    write(fd, "\r\n", 2);
}

void free_http_header(void *http_header, int from)
{
    void *header;
    switch(from)
    {
        case REQUEST:  header = (http_request_t *)http_header;  break;
        case RESPONSE: header = (http_response_t *)http_header; break;
        default:
                       exit(0);  /* 通过退出进程的方式隐式回收 */
    }
    struct list_head *pos = (header.head).next;
    while(pos != &(header.head))
    {
        struct list_head *temp = pos->next;
        http_field_t *field = list_entry(pos, http_field_t, list);
        printf("%s: %s\n", field->key, field->value);
        SAFE_FREE(field);
        pos = temp;
    }
}


PCRE2_SPTR replace_content_default_m(char *old)
{
    PCRE2_SPTR new;
    struct list_head *head = get_list_substring_compiled_code(old, re);
    if(head == NULL)
        return NULL;
    pad_list_rplstr_malloc(head, pad_remap_rplstr_malloc, remap_table, 2);
    new = replace_all_default_malloc(old, head);
    if(NULL == new)
    {
        free_list_substring(&head);
        return NULL;
    }
    free_list_substring(&head);
    SAFE_FREE(new);
}

int foward_http_chunked(int s_fd, int c_fd);
{
    char s_cnt[64] = {0};
    uint32_t cnt = 0;
    uint32_t n;
    char buff[LEN_BODY] = {0};
    char *ptr = buff;
    int tot_buf = 0;
    int left = sizeof(buff);
    int read_size = 1;
    while(1)            /* this while loop if for transfer chunk_size and chunk_data */
    {
        char chunk_size[33] = {0};
        if(read_size)
        {
            n = read_line(s_fd, s_cnt, sizeof(s_cnt));
            /* 25\r\n */
            if(strcmp(s_cnt, "0\r\n"))
                break;
            erase_ndigit(s_cnt);
            /* 25  */
            hex2dec(s_cnt, &cnt);
        }
        if(cnt <= left && cnt > 0)
        {
            cnt = readn(s_fd, ptr, cnt);
            ptr += cnt;
            left -= cnt;
            read_size = 1;  /* 读完chunked正文后,肯定要读取一下chunked的size */
        }
        else
        {
            /* 替换转发 */
            read_size = 0;
            PCRE2_SPTR new_chunked = replace_content_default_m(buff);
            if(NULL == new_chunked)
            {
                sprintf(chunk_size, "%x\r\n", LEN_BODY - left);
                write(c_fd, chunk_size, strlen(chunk_size));
                write(c_fd, buff, LEN_BODY - left);
            }
            else
            {
                sprintf(chunk_size, "%x\r\n", strlen(new));
                write(c_fd, chunk_size, strlen(chunk_size));
                write(c_fd, new, strlen(new));
                free(new);
            }
            memset(buff, 0, sizeof(buff));
            left = sizeof(buff);
            ptr = buff;
        }
    }


    while((n = read(s_fd, buff, sizeof(buff))))    /* this while loop is for chunk 拖挂内容 */
    {
        write(c_fd, buff, c_fd);
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
        printf("hex[%d]=%c\n", i, hex[i]);
        if(hex[i] >= '0' && hex[i] <= '9')
            truth = hex[i] - '0';
        else if(hex[i] >= 'a' && hex[i] <= 'f')
            truth = hex[i] - 'a' + 10;
        else if(hex[i] >= 'A' && hex[i] <= 'F')
            truth = hex[i] - 'A' + 10;
        else 
            return -1;
        power = max_power - i - 1;
        printf("truth=%d, power=%d\n", truth, power);
        *dec += (unsigned int)(truth*pow(16, power));
    }
    return 0;
}

int erase_ndigit(char *chunk_size)
{
    int len = strlen(chunk_size);
    int i = 0;
    for(i = 0; i < len, i++)
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
        http_field_t *field = list_enrty(pos, http_field_t, list);
        if(strcasecmp("Content-length", field->key))
        {
            memset(field->value, 0, LEN_FIELD_VLAUE);
            return sprintf(field->value, "%s", content_length);
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
            str[end] = '\0';
        }
        else
        {
            /* http://192.168.1.33 --> / */
            memset(req->url, 0, LEN_URL);
            strcpy(req->url, "/");
        }
    }
}

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
    n = read(fd, pattern, buffer.st_size)
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

int main(int argc, char **argv)
{
    if(argc != 3)
    {
        printf("Usage: %s port pattern_file\n", argv[0]);
        return 0;
    }

    /* 创建监听套接字 */
    short l_port = (short)aoti(argv[1]);
    int   l_fd = create_proxy_server(l_port);

    int c_fd;
    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    socklen_t s_len = sizeof(client_addr);
    char c_ip[LEN_IP] = {0};

    /* 注册信号处理函数 */
    if(signal(SIGCHLD, wait_child) == SIG_ERR)
        err_quit("signal");

    /* 获取pattern并编译 */
    char *pattern = get_pattern_m(argv[2]);
    if(NULL == pattern)
        err_quit("get_pattern failed, IGNORE ERROR MSG");

    re = get_compile_code((PCRE2_SPTR)pattern, 0);
    if(NULL == re)
        err_quit("pcre2 pattern init failed, IGNORE ERROR MSG");
    SAFE_FREE(pattern);

    /* 获取remap_table */
    remap_table = get_remap_table_m();
    if(NULL == remap_table)
        err_quit("get_remap_table_m failed, IGNORE ERROR MSG");

    while(1)
    {
        /* 父进程只做监听 */
        c_fd = accept(l_fd, (struct sockaddr *)&client_addr, &s_len);
        printf("client online :%s, %d\n", 
                inet_ntop(AF_INET, &client_addr.sin_addr.s_addr, c_ip, sizeof(c_ip)), 
                ntohs(client_addr.sin_port));
        pid_t pid = fork();
        if(pid < 0)
            err_quit("fork");   //是否要quit?
        else if(pid == 0)
        {
            close(l_fd);
            handle_client();    /* 创建两个子进程，一个转发c->s,一个转发s->c */
            close(c_fd);
            exit(0);
        }
        else
            close(c_fd);
    }

    return 0;
}

