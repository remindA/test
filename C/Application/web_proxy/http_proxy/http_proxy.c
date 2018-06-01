#include <time.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <zlib.h>
#include <assert.h>

#include "err_quit.h"
#include "http.h"
#include "list.h"
#include "safe_free.h"
#include "include.h"
#include "socket_tools.h"

extern int h_errno;    /* for get hostbyname #include <netdb.h> */

/* system may failed somtimes, wo need to change signal behavior of SIG_CHLD */
typedef void(*sighandler_t)(int);

/* 其他 */
int l_fd;

void usage(const char *name);
void sig_handler(int signo);
int proxy_listen(void);
void worker_thread(void *ARG);
int read_process_forward(int fd_from,  int *fd_to);
int process_first_request(int *fd_to, const char *host, unsigned short port);

int process_none(int fd_to, http_header_t *header);
int process_http_len(int fd_from, int fd_to, http_header_t *header, int len);
int process_http_chk(int fd_from, int fd_to, http_header_t *header);
int process_http_none(int fd_from, int fd_to, http_header_t *header);


int http_read_forward_chk(int fd_from, int fd_to);
int http_read_forward_len(int fd_from, int fd_to, int len_body);
int forward_http_chunk(int fd, http_chunk_t *chunk);
int rewrite_http_url(char *url, int max);


int main(int argc, char **argv)
{
    //监听的端口，缺省使用默认值
    int opt;
    if(argc == 2) {
        while((opt = getopt(argc, argv, "dsv")) != -1) {
            switch(opt) {
                case 'v':
                    printf("%s_%s\n", argv[0], VERSION);
                    return 0;
                default:
                    usage(argv[0]);
                    return 0;
            }
        }
    }

    openlog("http_proxy", LOG_CONS, LOG_USER);

    /* 建立socket */
    int   l_num = 500;
    char  l_host[] = "0.0.0.0";
    short l_port = HTTP_PROXY_PORT;
    l_fd = create_server_socket(l_host, l_port, l_num);
    if(l_fd < 0) {
        printf("cannot create proxy server\n");
        syslog(LOG_INFO, "create proxy server failed");
        return 0;
    }
    /* 监听 */
    switch(fork()) {
        case 0:
            printf("%s在后台启动\n", argv[0]);
            syslog(LOG_INFO, "%s程序启动.", argv[0]); 
            proxy_listen();
            exit(0);
        case -1:
            printf("fork()监听进程失败\n");
            syslog(LOG_INFO, "%s启动失败: fork failed", argv[0]); 
            err_quit("fork()");
            break;
        default:
            break;
    }
    return 0;
}

void usage(const char *name)
{
    printf("%s [option]\n", name);
    printf("\t-d \tAs http_proxy, listen on port %d\n", HTTP_PROXY_PORT);
    printf("\t-s \tAs https_proxy, listen on port %d\n", HTTPS_PROXY_PORT);
    printf("\t-v \tVersion\n");
}

/*
 *  worker:
 *          SIGPIPE: 忽略
 *          SIGHUP: 退出进程
 *  
 */
void sig_handler(int signo)
{
    switch(signo) {
        case SIGPIPE:
            syslog(LOG_INFO, " ignore SIGPIPE");
            break;
        default:
            syslog(LOG_INFO, " exit because of sig_%d", signo);
            exit(1);
    }
}


int proxy_listen(void)
{
    printf("\n==========start proxy_listen(%d)==========\n", getpid());
    if(signal(SIGINT, sig_handler) == SIG_ERR) {
        err_quit("signal()");
    }
    printf("register SIGINT=%d\n", SIGINT);

    if(signal(SIGSEGV, sig_handler) == SIG_ERR) {
        err_quit("signal()");
    }
    printf("register SIGSEGV=%d\n", SIGSEGV);

    if(signal(SIGPIPE, sig_handler) == SIG_ERR) {
        err_quit("signal()");
    }
    printf("register SIGPIPE=%d\n", SIGPIPE);

    if(signal(SIGUSR1, sig_handler) == SIG_ERR) {
        err_quit("signal()");
    }
    printf("register SIGUSR1=%d\n", SIGUSR1);

    if(signal(SIGUSR2, sig_handler) == SIG_ERR) {
        err_quit("signal()");
    }
    printf("register SIGUSR2=%d\n", SIGUSR2);

    struct sockaddr_in client_addr;
    bzero(&client_addr, sizeof(client_addr));
    socklen_t len_client = sizeof(client_addr);
    while(1) {
        int c_fd = accept(l_fd, (struct sockaddr *)&client_addr, &len_client);
        if(c_fd < 0) {
            perror("cannot accept correctly, accept()");
            continue;
        }
        int *fd = (int *)malloc(sizeof(int));
        if(NULL == fd) {
            perror("malloc()");
            continue;
        }
        *fd = c_fd;
        pthread_t th3;
        if(pthread_create(&th3, NULL, (void *)worker_thread, (void *)fd) < 0) {
            perror("pthread_create()");
            close(*fd);
            SAFE_FREE(fd);
        }
    }
    //隐式回收
    printf("==========finish proxy_listen()==========\n");
    return 0;
}

void worker_thread(void *ARG)
{
    /* thread init */
    int ret;
    int tid = getpid();
    pthread_detach(pthread_self());
    int c_fd = *((int *)ARG);
    SAFE_FREE(ARG);

    int s_fd = -1;
    while(1) {
        ret = read_process_forward(c_fd, &s_fd);
        if(ret < 0) {
            break;
        }
        else if(ret == 0) {
            break;
        }
        ret = read_process_forward(s_fd, &c_fd);
        if(ret < 0) {
            break;
        }
        else if(ret == 0) {
            break;
        }
    }
worker_exit:

    /*
     * 没用shutdown
     * 因为这里的close引用计数只有1
     * 效果等同
     */
    close(c_fd);
    if(s_fd > 0) {
        close(s_fd);
    }
#ifdef DEBUG
    printf("==========worker_thread() exit==========\n");
#endif
    pthread_exit(&ret);
}



/*
 * return: 
 *  <= 0 : failed
 *  > 0  : ok
 *  第一次调用时:(肯定是request)
 *      会在函数内解析header
 *      然后connect到真正服务器的地址，保存fd_to, regex
 *      根据服务器地址确定正则表达式
 *  第二次调用就是response
 *
 *  之后的每次调用都是一次request，一次response
 */
int read_process_forward(int fd_from,  int *fd_to)
{
#ifdef RPS
    printf("==========start read_process_forward()==========\n");
#endif
    int  pr;
    int  len;
    int  ret;
    int  req_or_rsp;
    unsigned short port;
    char host[LEN_HOST] = {0};
    char buff_header[LEN_HEADER] = {0};

    /* 1. 读http头 */
    ret = read_http_header(fd_from, buff_header, sizeof(buff_header) - 1);
    if(ret <= 0) {
#ifdef RPS
        printf("cannot read_http_header\n");
#endif
        return ret;
    }

    /* 2. 解析http头 */
    http_header_t header;
    memset(&header, 0, sizeof(http_header_t));
    init_list_head(&(header.head));

    if(parse_http_header(buff_header, &header) < 0) {
#ifdef RPS
        printf("cannot parse_http_header(%s)\n", buff_header);
#endif
        syslog(LOG_INFO, "read_http_header cannot");
        return -1;
    }

    req_or_rsp = is_http_req_rsp(&header);
    /* 3. 获取host:port和before_ip, 这里的host是映射后的地址 */
    /* 第一次请求包, 创建连接, 获取服务器的session*/
    if(req_or_rsp == IS_REQUEST && *fd_to < 0) {
        get_host_port(&header, host, &port);
        if(process_first_request(fd_to, host, port) < 0) {
            free_http_header(&header);
            return -1;
        }
    }

    if(req_or_rsp == IS_REQUEST) {
        rewrite_http_url(header.url, strlen(header.url));
    }

    /* 集成encd到header中 */
    len = get_pr_encd(&header, &pr);

#ifdef RPS
    printf("len = %d, pr = %d, encd = %d\n", len, pr);
#endif
    /* 7. 根据优先级替换转发 */
    switch(pr) {
        case PR_HTTP_LEN:
            printf("pr_len\n");
            ret = process_http_len(fd_from, *fd_to, &header, len);
            break;

        case PR_HTTP_CHK:
            printf("pr_none_txt_chk\n");
            ret = process_http_chk(fd_from, *fd_to, &header);
            break;

        case PR_HTTP_NONE:
            printf("pr_none_txt_none\n");
            ret = process_http_none(fd_from, *fd_to, &header);
            break;

        case PR_NONE:
        default:
            printf("pr_none\n");
            ret = process_none(*fd_to, &header);
            break;
    }
#ifdef RPS
    printf("==========finish read_process_forward()==========\n");
#endif
    free_http_header(&header);
    return ret;
}


int process_first_request(int *fd_to, const char *host, unsigned short port)
{
    int ret;
#ifdef TIME_COST
    struct timeval strt;
    struct timeval end;
    gettimeofday(&strt, NULL);
#endif
    *fd_to = connect_to_server(host, port);
    if(*fd_to < 0) {
        return -1;
    }
    return 1;
}

/*
 *
 */
int process_none(int fd_to, http_header_t *header)
{
    int  ret;
    char buff_header[LEN_HEADER] = {0};
    http_header_tostr(header, buff_header);
    ret = my_write(fd_to, "ld", strlen(buff_header), buff_header);
    return ret<0?ret:1;
}


/*
 * return:
 *      ok      : 1
 *      failed  : <=0 
 */
int process_http_len(int fd_from, int fd_to, http_header_t *header, int len)
{
    int  ret;
    char buff_header[LEN_HEADER] = {0};
    http_header_tostr(header, buff_header);
    ret = my_write(fd_to, "ld", strlen(buff_header), buff_header);
    if(ret < 0) {
        return -1;
    }

    ret = http_read_forward_len(fd_from, fd_to, len);
    return ret<=0?ret:1;
}

/*
 * return:
 *      ok      : 1
 *      failed  : <=0
 */
int process_http_chk(int fd_from, int fd_to, http_header_t *header)
{
    int  ret;
    char buff_header[LEN_HEADER] = {0};
    http_header_tostr(header, buff_header);
    ret = my_write(fd_to, "ld", strlen(buff_header), buff_header);
    if(ret < 0) {
        return -1;
    }
    ret = http_read_forward_chk(fd_from, fd_to);
    return ret<=0?ret:1;
}

int process_http_none(int fd_from, int fd_to, http_header_t *header)
{
    /* 肯定是connection-close */
    int  ret;
    char buff_header[LEN_HEADER] = {0};
    http_header_tostr(header, buff_header);
    ret = my_write(fd_to, "ld", strlen(buff_header), buff_header);
    if(ret < 0) {
        return -1;
    }
    /* 可能有body,接收转发,长度未知 */
    while((ret = http_read_forward_len(fd_from, fd_to, LEN_SSL_RECORD)) == 1) ;
    return ret;
}


int http_read_forward_chk(int fd_from, int fd_to)
{
#ifdef FUNC
    printf("==========start read_forward_chunk()==========\n");
#endif
    while(1) {
        int   ret;
        http_chunk_t chunk;
        memset(&chunk, 0, sizeof(chunk));
        ret = read_parse_chunk(fd_from, &chunk);
        if(ret <= 0) {
            free_http_chunk(&chunk);
            return ret;
        }
        ret = forward_http_chunk(fd_to, &chunk);
        if(ret <= 0) {
            return ret;
        }
        int size = chunk.chk_size;
        free_http_chunk(&chunk);
        if(size <= 0) {
            break;
        }
    }

#ifdef FUNC
    printf("==========finish read_forward_chunk()==========\n");
#endif
    return 1;
}


int forward_http_chunk(int fd, http_chunk_t *chunk)
{
    int  ret;
    unsigned int  len;
    unsigned char *buff = NULL;
    http_chunk_to_buff(chunk, &buff, &len);
    ret = my_write(fd, "ld", len, buff); 
    SAFE_FREE(buff);
    return ret;
}


/* 
 * return :
 *      ok      : 1
 *      failed  : <=0
 */
int http_read_forward_len(int fd_from, int fd_to, int len_body)
{
#ifdef FUNC
    printf("==========start read_forward_none_txt==========\n");
#endif
    int rd;
    int mywr;
    int real_read;
    int left;
    int tot = 0;
    left = len_body;
    char body[LEN_SSL_RECORD] = {0};
    while(left > 0) {
        /* 读取大小要限制在缓冲区的范围内 */
        rd = left<=sizeof(body)?left:sizeof(body);
        real_read = read(fd_from, body, rd);
        if(real_read < 0) {
            perror("read()");
            if(errno == EINTR) {
                continue;
            }
            else {
                return -1;
            }
        }
        else if(real_read == 0) {
            break;
        }
        else {
            left -= real_read;
            tot  += real_read;
            mywr = my_write(fd_to, "ld", real_read, body);
            if(mywr < 0) {
                return -1;
            }
        }
    }
#ifdef FUNC
    printf("==========finish read_forward_none_txt==========\n");
#endif
    return tot;
}




int rewrite_http_url(char *url, int max)
{
#ifdef FUNC
    printf("==========start rewrite_url()==========\n");
#endif

    /* 重写格式 */
    /* url中的协议名和域名部分不区分大小写, 路径区分大小写 */
    int len;
    char *start = url;
    while(*start == ' ') start++;
    char *p = strcasestr(start, "http://");
    /* 如果GET提交表单中含有http://，不作数 */
    if(p && p==start) {
        char *p1 = strchr(p + 7, '/');
        if(p1) {
            /* http://192.168.1.33/setup.cgi?ip1=192.168.1.33&ip2=192.168.1.22  --> /setup.cgi?ip1=192.168.1.33&ip2=192.168.1.22 */
            len = strlen(p1);
            memmove(url, p1, strlen(p1));
            *(url + len) = '\0';
        }
        else {
            /* http://192.168.1.33 --> / */
            memset(url, 0, LEN_URL);
            strcpy(url, "/");
        }
    }

#ifdef FUNC
    printf("==========finish rewrite_url()==========\n");
#endif
    return 0;
}

