#include <time.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
/* ulibc: __USE_GUN
 * glibs: _GNU_SOURCE
 */
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
extern int proxy;      /* define in socket_tools.c */

/* system may failed somtimes, wo need to change signal behavior of SIG_CHLD */
typedef void(*sighandler_t)(int);

/* openssl */
SSL_CTX *ctx_s;
SSL_CTX *ctx_c;
//char *ca_cert_file = "/etc/https_proxy/ca.crt";
char *server_cert_file = "/etc/http_proxy/server.crt";
char *private_key_file = "/etc/http_proxy/server.key";


/* 其他 */
int l_fd;

void usage(const char *name);
void sig_handler(int signo);
int ssl_init(void);
int proxy_listen(void);
void worker_thread(void *ARG);
int read_process_forward(int fd_from,  SSL *ssl_from, int *fd_to, SSL **ssl_to);
int process_first_request(int *fd_to, SSL **ssl_to, const char *host, unsigned short port);

int process_none(int fd_to, SSL *ssl_to, http_header_t *header);
int process_http_len(int fd_from, SSL *ssl_from, int fd_to, SSL *ssl_to, http_header_t *header, int len);
int process_http_chk(int fd_from, SSL *ssl_from, int fd_to, SSL *ssl_to, http_header_t *header);
int process_http_none(int fd_from, SSL *ssl_from, int fd_to, SSL *ssl_to, http_header_t *header);


int http_read_forward_chk(int fd_from, SSL *ssl_from, int fd_to, SSL *ssl_to);
int http_read_forward_len(int fd_from, SSL *ssl_from, int fd_to, SSL *ssl_to, int len_body);
int forward_http_chunk(int fd, SSL *ssl, http_chunk_t *chunk);
int rewrite_http_url(char *url, int max);


int main(int argc, char **argv)
{
    //监听的端口，缺省使用默认值
    int opt;
    if(argc != 2) {
        usage(argv[0]);
        return 0;
    }
    while((opt = getopt(argc, argv, "dsv")) != -1) {
        switch(opt) {
            case 's':
                proxy = HTTPS;
                break;
            case 'd':
                proxy = HTTP;
                break;
            case 'v':
                printf("%s_%s\n", argv[0], VERSION);
                return 0;
            default:
                usage(argv[0]);
                return 0;
        }
    }

    openlog("http_proxy", LOG_CONS, LOG_USER);

    /* 初始化openssl, ctx_s, ctx_c等 */
    if(proxy == HTTPS && ssl_init() < 0) {
        fprintf(stderr, "cannot ssl_init()\n");
        syslog(LOG_INFO, "ssl_init failed");
        return 0;
    }

    /* 建立socket */
    int   l_num = 100;
    char  l_host[] = "0.0.0.0";
    short l_port = (proxy == HTTP)?HTTP_PROXY_PORT:HTTPS_PROXY_PORT;
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
            if(proxy == HTTP) {
                syslog(LOG_INFO, "%s程序启动: http proxy", argv[0]); 
            }
            if(proxy == HTTPS) {
                syslog(LOG_INFO, "%s程序启动: https proxy", argv[0]); 
            }
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
        case SIGUSR1:
            if(proxy == HTTP) {
                syslog(LOG_INFO, "http_proxy exit SIGUSR1");
                exit(1);
            }
            break;
        case SIGUSR2:
            if(proxy == HTTPS){
                syslog(LOG_INFO, "https_proxys exit SIGUSR2");
                exit(1);
            }
            break;
        case SIGPIPE:
            if(proxy == HTTP) {
                syslog(LOG_INFO, "http_proxy ignore SIGPIPE");
            }
            if(proxy == HTTPS) {
                syslog(LOG_INFO, "http_proxys ignore SIGPIPE");
            }
            break;
        case SIGINT:
            if(proxy == HTTP) {
                syslog(LOG_INFO, "http_proxy ignore SIGINT");
            }
            if(proxy == HTTPS) {
                syslog(LOG_INFO, "http_proxys ignore SIGINT");
            }
            break;
        default:
            if(proxy == HTTP) {
                syslog(LOG_INFO, "http_proxy exit because of sig_%d", signo);
            }
            if(proxy == HTTPS) {
                syslog(LOG_INFO, "http_proxys exit because of sig_%d", signo);
            }
            exit(1);
    }
}


int ssl_init(void)
{ 
#ifdef FUNC
    printf("==========start ssl_init()==========\n");
#endif
    SSL_load_error_strings();
    //OpenSSL_add_ssl_algorithms();
    SSL_library_init();

    ctx_c = SSL_CTX_new(TLSv1_2_client_method());  //代理客户端
    if(!ctx_c) {
#ifdef DEBUG_SSL
        printf("cannot create ctx_c\n");
#endif
        return -1;
    }
    ctx_s = SSL_CTX_new(TLSv1_2_server_method());  //代理服务器
    if(!ctx_s) {
#ifdef DEBUG_SSL
        printf("cannot create ctx_s\n");
#endif
        return -1;
    }

    //SSL_CTX_set_verify(ctx_s, SSL_VERIFY_NONE, NULL);
    //SSL_CTX_set_verify(ctx_s, SSL_VERIFY_PEER, NULL);
    //SSL_CTX_load_verify_locations(ctx_s, ca_cert_file, NULL);
    if(SSL_CTX_use_certificate_file(ctx_s, server_cert_file, SSL_FILETYPE_PEM) <= 0) {
#ifdef DEBUG_SSL
        printf("cannot load server certificate file\n");
#endif
        return -1;
    }
    if(SSL_CTX_use_PrivateKey_file(ctx_s, private_key_file, SSL_FILETYPE_PEM) <= 0) {
#ifdef DEBUG_SSL
        printf("cannot load server private key file\n");
#endif
        return -1;
    }
    if(!SSL_CTX_check_private_key(ctx_s)) {
#ifdef DEBUG_SSL
        printf("cannot match server_cert_file and private_key_file\n");
#endif
        return -1;
    }
    //SSL_CTX_set_cipher_list(ctx_s, "RC4-MD5");
    //SSL_CTX_set_cipher_list(ctx_s, "AES256-GCM-SHA384");
    SSL_CTX_set_cipher_list(ctx_s, "ALL");
    SSL_CTX_set_mode(ctx_s, SSL_MODE_AUTO_RETRY);
#ifdef FUNC
    printf("==========finish ssl_init()==========\n");
#endif
    return 0;
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
    SSL *ssl_s = NULL;
    SSL *ssl_c = NULL;
    if(proxy == HTTPS) {
#ifdef TIME_COST
        struct timeval st;
        struct timeval ed;
        gettimeofday(&st, NULL);
#endif
        /* ssl */
        ssl_s = SSL_new(ctx_s);
        if(NULL == ssl_s) {
            printf("handle_client(%d): cannot create ssl\n", tid);
            goto worker_exit;
        }
        ret = SSL_set_fd(ssl_s, c_fd);
        if(ret != 1) {
            print_ssl_error(ssl_s, ret, "handle_client: SSL_set_fd");
            goto worker_exit;
        }
        if((ret = SSL_accept(ssl_s)) == 0) {
            print_ssl_error(ssl_s, ret, "handle_client: SSL_accept()");
            goto worker_exit;
        }
#ifdef TIME_COST
        gettimeofday(&ed, NULL);
        printf("ssl_accept total use  %ldms\n", (ed.tv_sec-st.tv_sec)*1000 + (ed.tv_usec-st.tv_usec)/1000);
        syslog(LOG_INFO, "ssl_accept total use  %ldms\n", (ed.tv_sec-st.tv_sec)*1000 + (ed.tv_usec-st.tv_usec)/1000);
#endif
    }
    while(1) {
        ret = read_process_forward(c_fd, ssl_s, &s_fd, &ssl_c);
        if(ret < 0) {
            break;
        }
        else if(ret == 0) {
            break;
        }
        ret = read_process_forward(s_fd, ssl_c, &c_fd, &ssl_s);
        if(ret < 0) {
            break;
        }
        else if(ret == 0) {
            break;
        }
    }
worker_exit:
    if(ssl_s != NULL) {
        SSL_shutdown(ssl_s);
        SSL_free(ssl_s);
    }
    if(ssl_c != NULL) {
        SSL_shutdown(ssl_c);
        SSL_free(ssl_c);
    }

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
 *      然后connect到真正服务器的地址，保存fd_to, ssl_to(https), regex
 *      根据服务器地址确定正则表达式
 *  第二次调用就是response
 *
 *  之后的每次调用都是一次request，一次response
 */
int read_process_forward(int fd_from,  SSL *ssl_from, int *fd_to, SSL **ssl_to)
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
    ret = read_http_header(fd_from, ssl_from, buff_header, sizeof(buff_header) - 1);
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
        if(process_first_request(fd_to, ssl_to, host, port) < 0) {
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
            ret = process_http_len(fd_from, ssl_from, *fd_to, *ssl_to, &header, len);
            break;

        case PR_HTTP_CHK:
            printf("pr_none_txt_chk\n");
            ret = process_http_chk(fd_from, ssl_from, *fd_to, *ssl_to, &header);
            break;

        case PR_HTTP_NONE:
            printf("pr_none_txt_none\n");
            ret = process_http_none(fd_from, ssl_from, *fd_to, *ssl_to, &header);
            break;

        case PR_NONE:
        default:
            printf("pr_none\n");
            ret = process_none(*fd_to, *ssl_to, &header);
            break;
    }
#ifdef RPS
    printf("==========finish read_process_forward()==========\n");
#endif
    free_http_header(&header);
    return ret;
}


int process_first_request(int *fd_to, SSL **ssl_to, const char *host, unsigned short port)
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

    /* https ssl connection */
    if(proxy == HTTPS) {

        *ssl_to = SSL_new(ctx_c);
        if(NULL == *ssl_to) {
            printf("cannot SSL_new\n");
            close(*fd_to);
            return -1;
        }
        ret = SSL_set_fd(*ssl_to, *fd_to);
        if(ret != 1) {
            print_ssl_error(*ssl_to, ret, "SSL_set_fd ssl_c");
            close(*fd_to);
            SSL_free(*ssl_to);
            return -1;
        }
        ret = SSL_connect(*ssl_to);
        if(ret <= 0) {
            print_ssl_error(*ssl_to, ret, "SSL_connect ssl_c");
            close(*fd_to);
            SSL_free(*ssl_to);
            return -1;
        }
#ifdef TIME_COST
        gettimeofday(&end, NULL);
        printf("tcp_ssl_connect total use %ldms\n",
                (end.tv_sec-strt.tv_sec)*1000 + (end.tv_usec-strt.tv_usec)/1000);
#endif
    }
    return 1;
}

/*
 *
 */
int process_none(int fd_to, SSL *ssl_to, http_header_t *header)
{
    int  ret;
    char buff_header[LEN_HEADER] = {0};
    http_header_tostr(header, buff_header);
    ret = my_write(fd_to, ssl_to, "ld", strlen(buff_header), buff_header);
    return ret<0?ret:1;
}


/*
 * return:
 *      ok      : 1
 *      failed  : <=0 
 */
int process_http_len(int fd_from, SSL *ssl_from, int fd_to, SSL *ssl_to, http_header_t *header, int len)
{
    int  ret;
    char buff_header[LEN_HEADER] = {0};
    http_header_tostr(header, buff_header);
    ret = my_write(fd_to, ssl_to, "ld", strlen(buff_header), buff_header);
    if(ret < 0) {
        return -1;
    }

    ret = http_read_forward_len(fd_from, ssl_from, fd_to, ssl_to, len);
    return ret<=0?ret:1;
}

/*
 * return:
 *      ok      : 1
 *      failed  : <=0
 */
int process_http_chk(int fd_from, SSL *ssl_from, int fd_to, SSL *ssl_to, http_header_t *header)
{
    int  ret;
    char buff_header[LEN_HEADER] = {0};
    http_header_tostr(header, buff_header);
    ret = my_write(fd_to, ssl_to, "ld", strlen(buff_header), buff_header);
    if(ret < 0) {
        return -1;
    }
    ret = http_read_forward_chk(fd_from, ssl_from, fd_to, ssl_to);
    return ret<=0?ret:1;
}

int process_http_none(int fd_from, SSL *ssl_from, int fd_to, SSL *ssl_to, http_header_t *header)
{
    /* 肯定是connection-close */
    int  ret;
    char buff_header[LEN_HEADER] = {0};
    http_header_tostr(header, buff_header);
    ret = my_write(fd_to, ssl_to, "ld", strlen(buff_header), buff_header);
    if(ret < 0) {
        return -1;
    }
    /* 可能有body,接收转发,长度未知 */
    while((ret = http_read_forward_len(fd_from, ssl_from, fd_to, ssl_to, LEN_SSL_RECORD)) == 1) ;
    return ret;
}


int http_read_forward_chk(int fd_from, SSL *ssl_from, int fd_to, SSL *ssl_to)
{
#ifdef FUNC
    printf("==========start read_forward_chunk()==========\n");
#endif
    while(1) {
        int   ret;
        http_chunk_t chunk;
        memset(&chunk, 0, sizeof(chunk));
        ret = read_parse_chunk(fd_from, ssl_from, &chunk);
        if(ret <= 0) {
            free_http_chunk(&chunk);
            return ret;
        }
        ret = forward_http_chunk(fd_to, ssl_to, &chunk);
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


int forward_http_chunk(int fd, SSL *ssl, http_chunk_t *chunk)
{
    int  ret;
    unsigned int  len;
    unsigned char *buff = NULL;
    http_chunk_to_buff(chunk, &buff, &len);
    ret = my_write(fd, ssl, "ld", len, buff); 
    SAFE_FREE(buff);
    return ret;
}


/* 
 * return :
 *      ok      : 1
 *      failed  : <=0
 */
int http_read_forward_len(int fd_from, SSL *ssl_from, int fd_to, SSL *ssl_to, int len_body)
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
        real_read = (proxy==HTTPS)?SSL_read(ssl_from, body, rd):read(fd_from, body, rd);
        if(real_read < 0) {
            if(proxy == HTTPS) print_ssl_error(ssl_from, real_read, "read_forward_none_txt");
            else perror("read()");

            if(errno == EINTR) {
                continue;
            }
            else {
                return -1;
            }
        }
        else if(real_read == 0) {
            if(proxy == HTTPS) print_ssl_error(ssl_from, real_read, "read_forward_none_txt");
            break;
        }
        else {
            left -= real_read;
            tot  += real_read;
            mywr = my_write(fd_to, ssl_to, "ld", real_read, body);
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

