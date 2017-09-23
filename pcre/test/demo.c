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

remap_t remap_table[2] = {
    {"192.168.1.33", "172.27.5.33"},
    {"127.0.0.1", "192.168.1.102"}
};


//效率太低，后面再改
void replace_field_xx(const char *pattern, char *field_value)
{
    printf("before replace value=%s\n", field_value);
    PCRE2_SPTR subject = (PCRE2_SPTR)field_value;
    struct list_head *head = get_list_substring_pattern(subject, (PCRE2_SPTR)pattern, 0);
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
    struct list_head *pos = NULL;
    //char *pat_ip = "(([0-1]\\d?\\d|2[0-4]\\d|25[0-5]).){3}([0-1]\\d?\\d|2[0-4]\\d|25[0-5])";
    char *pat_ip = "127.0.0.1";
    list_for_each(pos, head)
    {

        http_field_t *field = list_entry(pos,http_field_t, list);
        if(strcasecmp(field->key, "Host") == 0)
        {
            //replace ip;效率太低，后面再改
            replace_field_xx(pat_ip, field->value);
        }
        if(strcasecmp(field->key, "Referer") == 0)
        {
            //replace ip
            replace_field_xx(pat_ip, field->value);
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

int main(int argc, char **argv)
{
    if(argc != 2)
    {
        printf("Usage: %s port\n", argv[0]);
        return 0;
    }

    short l_port = (short)aoti(argv[1]);
    int   l_fd = create_proxy_server(l_port);

    int c_fd;
    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    socklen_t s_len = sizeof(client_addr);
    char c_ip[LEN_IP] = {0};

    if(signal(SIGCHLD, wait_child) == SIG_ERR)
        err_quit("signal");

    while(1)
    {
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
     * 子进程1:转发remap后的req_header
     *      　:过滤转发body
     * 子进程2:接收服务器回应的rsp_header
     *         remap rsp_header
     *         优先级识别
     *         转发remap后的rsp_header
     *         根据优先级转发body
     */

    http_request_t req_header;
    init_list_head(&(req_header.head));
    int ret;
    if((ret = parse_http_request_header(c_fd, &req_header)) < 0)
        exit(0);
    //rewrite_req_line_url(&req_header);
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
    case PR_CONTENT_LEN:
        {
            if(content_len > 0)
            {
                char *buf_body = (char *)malloc(content_len);
                memset(buf_body, 0, content_len);
                //rewrite_content_length(&rsp_head);
                forward_http_header(&rsp_head, RESPONSE);
                //接收body,替换,转发新body
            }
            else
                forward_http_header(&rsp_head, RESPONSE); 
            break;
        }
    case PR_CHUNKED:
        {
            forward_http_header(&rsp_head, RESPONSE);
            //开buf-->接收-->替换-->转发.
            break;
        }
    case PR_NONE_TXT:
    case PR_NONE:
    default:
        {
            forward_http_header(&rsp_head, RESPONSE);
            char buf_body[LEN_BODY] = {0};
            int n = 0;
            while((n = read(s_fd, buf_body, LEN_BODY)) > 0)
            {
                write(c_fd, buf_body, n);
                memset(buf_body, 0, LEN_BODY);
                //watch out SIG_PIPE
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
