/*
 * =====================================================================================
 *
 *       Filename:  https_proxy.c
 *
 *    Description:  https代理
 *
 *        Version:  1.0
 *        Created:  2018年01月04日 13时31分20秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#define PCRE2_CODE_UNIT_WIDTH 8
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
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <linux/prctl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include "err_quit.h"
#include "http.h"
#include "list.h"
#include "pad_rplstr.h"
#include "safe_free.h"
#include "include.h"
#include "str_replace.h"
#include "config.h"

extern int h_errno;    /* #include <netdb.h> */

#include <sys/ipc.h>
#include <sys/msg.h>



/* 消息队列=============线程传参 */
typedef struct _thread_arg {
    //SSL   *ssl;
    int fd;
    int  msgid;
    long msg_type;
}thread_arg_t;


#define MSG_FIRST  0
#define MSG_CLIENT 1
#define MSG_SERVER 2
#define MSG_HOST   3
#define MSG_END    4
#define MSG_FINISH 5
//#define LEN_SSL_REC 16384
#define LEN_SSL_REC 4096
#define LEN_MSG_QUEUE (LEN_SSL_REC + sizeof(int))

typedef struct {
    long type;
    unsigned short len;
    unsigned char data[LEN_SSL_REC];
}msg_t;

/* msgid_c转发client request */
/* msgid_s转发server reponse */
int msgid_c;
int msgid_s;

/* openssl */
SSL *ssl_s;
SSL *ssl_c;
SSL_CTX *ctx_s;
SSL_CTX *ctx_c;
char *ca_cert_file = "/etc/https_proxy/ca.crt";
char *server_cert_file = "/etc/https_proxy/server.crt";
char *private_key_file = "/etc/https_proxy/server.key";


/* 其他 */
int l_fd;
int c_fd;
int wake;
pcre2_code *re;
pcre2_code *ge_re;
struct list_head *remap_table;
struct list_head *regex_table;

/* 函数声明 */
typedef void(*sighandler_t)(int);
static inline int msg_queue_del(int msgid);
void msg_queue_destory_all();
int msg_queue_init();
    
int ssl_init(void);
int print_ssl_error(SSL *ssl, int ret);
int write_to_msg(thread_arg_t *arg, int len_limit, char *fmt, ...);
int handle_client();
void do_forward(void *ARG);
int handle_server();
int read_process_to_msg(thread_arg_t *arg);
//int get_all_chunk_m(SSL *ssl, unsigned char **all_chunk, unsigned int *len);
int get_all_chunk_m(int fd, unsigned char **all_chunk, unsigned int *len);
int forward_http_chunked(thread_arg_t *arg, int len_limit, int encd, int direction, pcre2_code *re);
int forward_txt(http_header_t *header, unsigned char *body, int len, int whole, int encd, thread_arg_t *arg, int len_limit, int direction, pcre2_code *re);
int read_forward_none_txt(thread_arg_t *arg, int len_limit, int len_body, const char *comment);
int create_proxy_server(char *host, short l_port, int listen_num);
int create_real_server(const char *host, short port);
int create_real_server_nonblock(const char *host, short port, int sec);
PCRE2_SPTR replace_content_default_m(char *old, int direction, pcre2_code *re);
int rewrite_url(char *url, pcre2_code *re);
int replace_field(char *field_value, int direction, pcre2_code *re);
int replace_http_header(http_header_t *header, pcre2_code *re);
int get_gunzip(unsigned char *src, unsigned int len_s, char **dst, unsigned int *len_d);
void sig_handle(int signo);
void sig_handle_2(int signo);
int proxy_listen(void);



static inline int msg_queue_del(int msgid)
{
    int ret = msgctl(msgid, IPC_RMID, NULL);
    if(ret < 0) {
        perror("msgctl");
    }
    return ret;
}


void msg_queue_destory_all()
{
    msg_queue_del(msgid_c);
    msg_queue_del(msgid_s);
}

int msg_queue_init()
{
    int ret;
    msgid_c = msgget(IPC_PRIVATE,  IPC_CREAT | IPC_EXCL | 0666);
    if(msgid_c < 0) {
        perror("msgget id_c");
        return -1;
    }
    printf("msgget msgid_c\n");

    msgid_s = msgget(IPC_PRIVATE,  IPC_CREAT | IPC_EXCL | 0666);
    if(msgid_s < 0) {
        perror("msgget id_s");
        msg_queue_del(msgid_c); 
        return -1;
    }
    printf("msgget msgid_s\n");

    return 0;
}
//int write_to_ipc(thread_arg_t *arg, int len_limit, char *fmt, ...)

int write_to_msg(thread_arg_t *arg, int len_limit, char *fmt, ...)
{
#ifdef FUNC
    printf("==========start write_to_msg()==========\n");
#endif
    va_list ap;
    int len = 0;
    int len_tot = 0;
    int offset = 0;
    unsigned char *buff;
    char *fmt_tmp = fmt;

    /* 总长度检查 */
    va_start(ap, fmt);
    while(*fmt) {
        switch(*fmt++) {
            case 'l':
                len = va_arg(ap, int);
                len_tot += len;
                break;
            case 'd':
                buff = va_arg(ap, unsigned char *);
            default: 
                break;
        }
    }
    //printf("write_to_msg len_tot = %d\n", len_tot);
    va_end(ap);
    fmt = fmt_tmp;
    va_start(ap, fmt);

    /* 总长度符合*/
    msg_t msg;
    if(len_tot <= len_limit && len_tot > 0) {
        offset = 0;
        while(*fmt) {
            switch(*fmt++) {
                case 'l':
                    len = va_arg(ap, int);
                    break;
                case 'd':
                    buff = va_arg(ap, unsigned char *);
                    memcpy(msg.data + offset, buff, len);
                    offset += len;
                    break;
                default:
                    break;

            }
        }
        msg.type = arg->msg_type;
        msg.len = offset;
        msgsnd(arg->msgid, &msg, sizeof(msg_t) - sizeof(long), 0);
        
    }
    /* 总长度不符合, 每个传入的串，但单独拷贝到共享内存 */
    else if(len_tot > len_limit) {
        //printf("write_to_msg: len_buff > len_limit, %d > %d\n", len_tot, len_limit);
        while(*fmt) {
            switch(*fmt++) {
                case 'l':
                    len = va_arg(ap, int);
                    break;
                case 'd':
                    {
                        int send = 0;
                        int left = len;
                        int tot_send = 0;
                        buff = va_arg(ap, unsigned char *);
                        while(left > 0) {
                            send = left<=len_limit?left:len_limit;
                            msg.type = arg->msg_type;
                            msg.len = send;
                            memcpy(msg.data, buff + tot_send, send);
                            msgsnd(arg->msgid, &msg, sizeof(msg_t) - sizeof(long), 0);
                            tot_send += send;
                            left -= send;
                        }
                        break;
                    }
                default:
                    break;
            }
        }

        /* 总长度OK */
        va_end(ap);
    }
    else {
        //printf("len is <=0 , wrong \n");
    }
#ifdef FUNC
    printf("==========finish write_to_msg()==========\n");
#endif
    return 0;
}


int ssl_init(void)
{ 
#ifdef FUNC
    printf("==========start ssl_init()==========\n");
#endif
    SSL_load_error_strings();
    //OpenSSL_add_ssl_algorithms();
    SSLeay_add_ssl_algorithms();

    ctx_c = SSL_CTX_new(TLSv1_client_method());  //代理客户端
    if(!ctx_c) {
#ifdef DEBUG_SSL
        printf("cannot create ctx_c\n");
#endif
        return -1;
    }

    ctx_s = SSL_CTX_new(TLSv1_server_method());  //代理服务器
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


int print_ssl_error(SSL *ssl, int ret)
{
    switch(SSL_get_error(ssl, ret)) {
        case SSL_ERROR_NONE:
            printf("ssl_error_none\n");
            return 0;
        case SSL_ERROR_ZERO_RETURN:
            printf("ssl_error_zero_return\n");
            break;
        case SSL_ERROR_WANT_READ:
            printf("ssl_error_want_read\n");
            break;
        case SSL_ERROR_WANT_WRITE:
            printf("ssl_error_want_write\n");
            break;
        case SSL_ERROR_WANT_CONNECT:
            printf("ssl_error_want_connect\n");
            break;
        case SSL_ERROR_WANT_ACCEPT:
            printf("ssl_error_want_accept\n");
            break;
        case SSL_ERROR_WANT_X509_LOOKUP:
            printf("ssl_error_want_x509_lookup\n");
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
            printf("ssl_error_syscall\n");
            break;
        case SSL_ERROR_SSL:
            printf("ssl_error_ssl\n");
            break;
        default:
            printf("ssl_error_unknown\n");
            break;
    }
    return -1;
}


int handle_client()
{
#ifdef FUNC
    printf("==========start handle_client(%d)==========\n", getpid());
#endif
    /* 1. 父进程退出时收到SIGHUP信号 */
    if(prctl(PR_SET_PDEATHSIG, SIGHUP, 0, 0, 0) == -1) {
        printf("cannot prctl()");
    }

    /* 2. 注册信号处理函数 */
    if(signal(SIGPIPE, sig_handle_2) == SIG_ERR) {
        err_quit("signal()");
    }
    if(signal(SIGINT, sig_handle_2) == SIG_ERR) {
        err_quit("signal()");
    }

    /* 子进程一旦退出，立刻退出。子进程保证所有数据正常转发 */
    if(signal(SIGCHLD, sig_handle_2) == SIG_ERR) {
        err_quit("signal()");
    }
    if(signal(SIGHUP, sig_handle_2) == SIG_ERR) {
        err_quit("signal()");
    }

    /* 3. ssl初始化 */
    int ret;
#if 0
    ssl_s = SSL_new(ctx_s);
    if(NULL == ssl_s) {
#ifdef DEBUG_SSL
        printf("cannot create ssl\n");
#endif
        return -1;
    }
#ifdef DEBUG_SSL
    printf("SSL_new ok\n");
#endif
    ret = SSL_set_fd(ssl_s, c_fd);
    if(ret != 1) {
#ifdef DEBUG_SSL
        printf("cannot SSL_set_fd()\n");
#endif
        print_ssl_error(ssl_s, ret);
        return -1;
    }
#ifdef DEBUG_SSL
    printf("SSL_set_fd ok\n");
#endif
    if((ret = SSL_accept(ssl_s)) == 0) {
#ifdef DEBUG_SSL
        printf("cannot SSL_accept()\n");
#endif
        print_ssl_error(ssl_s, ret);
        return -1;
    }
#ifdef DEBUG_SSL
    printf("SSL_accept ok\n");
#endif 
#endif

    /* 4. 信号量和共享内存初始化 */
    msg_queue_init();

    /* 5. 创建子进程，继承信号量＋共享内存 */
    pid_t child = fork();
    switch(child) {
        case -1:
            perror("handle_client, fork()");
            msg_queue_destory_all();
            exit(0);
        case 0:
            close(c_fd);
            /*
            SSL_free(ssl_s);
            SSL_CTX_free(ctx_s);
            */
            ret = handle_server();
            exit(ret);
        default:
            break;
    }

    //SSL_CTX_free(ctx_c);
    /* 6. 创建转发器线程 */
    //thread_arg_t arg = {ssl_s, msgid_s, MSG_SERVER};
    thread_arg_t arg = {c_fd, msgid_s, MSG_SERVER};
    pthread_t th;
    if(pthread_create(&th, NULL, (void *)do_forward, (void *)&arg) != 0) {
        perror("father, pthread_create()");
        msg_queue_destory_all();
        return -1;
    }

    /* 7. 读包－分析包－发包至转发器 */
    //thread_arg_t arg_2 = {ssl_s, msgid_c, MSG_CLIENT};
    thread_arg_t arg_2 = {c_fd, msgid_c, MSG_CLIENT};
    wake = 1;
    while((ret = read_process_to_msg(&arg_2)) > 0) ;

//#ifdef DEBUG
    printf("handle_client: read_process_to_msg returned\n");
//#endif
    /* a: 浏览器ssl握手后，毛线也没发就断开连接了,wake肯定为1
     * b: 若浏览器接收到了最后一个保报文,wake肯定为0.此时不能立刻退出进程
     *    要等数据服务器将数据发送至浏览器后再退出，这里用延时处理并不合适
     */
    if(ret == 0 && wake == 0) {
        sleep(TIMEOUT_CONNECT);
    }
    kill(child, SIGINT);
//#ifdef DEBUG
    printf("handle_client read_process_to_msg exit\n");
//#endif

    //SSL_shutdown(ssl_s);
    close(c_fd);
    //SSL_free(ssl_s);

    //共享内存和信号量的释放
    msg_queue_destory_all();

#ifdef FUNC
    printf("==========finish handle_client(%d)==========\n", getpid());
#endif
    return 0;
}


/*
 * do_forward: 把共享内存中的数据原样转发到对端
 * 在转发期间，要阻塞SIGCHLD信号
 */
void do_forward(void *ARG)
{
//#ifdef FUNC
    printf("==========start do_forward(%d) from %d==========\n", getpid(), getppid());
//#endif
    int len;
    int retval;
    pthread_detach(pthread_self());
    thread_arg_t *arg = (thread_arg_t *)ARG;
    msg_t msg;
    while(1) {
        msgrcv(arg->msgid, &msg, sizeof(msg_t) - sizeof(long), 0, 0);
        if(msg.type == MSG_END) {
            break;
        }
        //printf("===do_foward_%d: type = %d, len = %d\n", getpid(), msg.type, msg.len);
        int tot_wr = 0;
        int actual_wr = 0;
        while(msg.len - tot_wr > 0) {
            //actual_wr = SSL_write(arg->ssl, msg.data + tot_wr, msg.len - tot_wr);
            actual_wr = write(arg->fd, msg.data + tot_wr, msg.len - tot_wr);
            tot_wr += actual_wr;
        }
        //printf("===do_forward done once\n");
    }
//#ifdef FUNC
    /* 只有handle_client的do_forward线程会收到MSG_END消息,此时标志着,handle_client进程要退出 */
    msg_queue_destory_all();
    exit(0);
    printf("==========finish do_forward(%d)==========\n", getpid());
//#endif
    pthread_exit(&retval);
}


int handle_server()
{
#ifdef FUNC
    printf("==========start handle_server(%d)==========\n", getpid());
#endif
    /* 1. 父进程退出时收到SIGHUP信号 */
    if(prctl(PR_SET_PDEATHSIG, SIGHUP, 0, 0, 0) == -1) {
        printf("cannot prctl()");
    }

    /* 2. 注册信号处理函数 */
    if(signal(SIGPIPE, sig_handle) == SIG_ERR) {
        err_quit("signal()");
    }
    if(signal(SIGINT, sig_handle) == SIG_ERR) {
        err_quit("signal()");
    }
    if(signal(SIGHUP, sig_handle_2) == SIG_ERR) {
        err_quit("signal()");
    }

    /* 3. 等待唤醒消息 */
    int   ret;
    int   len;
    int   port;
    char  *host = (char *)malloc(LEN_HOST);
    memset(host, 0, LEN_HOST);

    msg_t msg;
    msgrcv(msgid_c, &msg, sizeof(msg_t) - sizeof(long), MSG_HOST, 0);
    if(msg.len <= 0) {
        printf("msgrcv host len = %d <= 0\n", msg.len);
        return -1;
    }
    msg.data[msg.len] = '\0';
    ret = sscanf(msg.data, "%[^:]:%d", host, &port);

    /* 4. 根据host来确定pcre2_code */
    re = get_re_by_host_port(regex_table, host, (short)port);
    if(NULL == re) {
        re = ge_re;
    }

    /* 5. 与服务器建立连接，绑定ssl */
    int s_fd = create_real_server_nonblock(host, port, TIMEOUT_CONNECT);
    if(s_fd < 0) {
#ifdef DEBUG
        printf("cannot create_real_server, %s:%d\n", host, (short)port);
#endif
        return -1;
    }
    SAFE_FREE(host);

#if 0
    ssl_c = SSL_new(ctx_c);
    if(NULL == ssl_c) {
#ifdef DEBUG_SSL
        printf("cannot SSL_new ssl_c\n");
#endif
        return -1;
    }
#ifdef DEBUG_SSL
    printf("SSL_new ssl_c ok\n");
#endif
    ret = SSL_set_fd(ssl_c, s_fd);
    if(ret != 1) {
        print_ssl_error(ssl_c, ret);
        close(s_fd);
        return -1;
    }
#ifdef DEBUG_SSL
    printf("SSL_set_fd ssl_c ok\n");
#endif
    ret = SSL_connect(ssl_c);
    if(ret <= 0) {
        printf("cannot SSL_connect ssl_c\n");
        print_ssl_error(ssl_c, ret);
        close(s_fd);
        return -1;
    }
#ifdef DEBUG_SSL
    printf("SSL_connect ssl_c ok\n");
#endif
#endif
    /* 6. 建立转发器线程 */
    //thread_arg_t arg = {ssl_c, msgid_c, MSG_CLIENT};
    thread_arg_t arg = {s_fd, msgid_c, MSG_CLIENT};
    pthread_t th;
    if(pthread_create(&th, NULL, (void *)do_forward, (void *)&arg) < 0) {
        perror("child, pthread_create()");
        return -1;
    }

    /* 7. 读包－分析包－发包至转发器 */
    //thread_arg_t arg_2 = {ssl_c, msgid_s, MSG_SERVER};
    thread_arg_t arg_2 = {s_fd, msgid_s, MSG_SERVER};
    wake = 0;
    while((ret = read_process_to_msg(&arg_2)) > 0) ;

    printf("handle_client: read_process_to_msg returned\n");

    //通知服务器转发结束
    msg.type = MSG_END;
    msgsnd(msgid_s, &msg, sizeof(msg_t) - sizeof(long), 0);

    /* 回收资源 */
    //SSL_shutdown(ssl_c);
    close(s_fd);
    //SSL_free(ssl_c);
#ifdef FUNC
    printf("==========finish handle_server(%d)==========\n", getpid());
#endif
    
    return ret;
}


/*
 * return: 
 *  <= 0 : failed
 *  > 0  : ok
 */
int read_process_to_msg(thread_arg_t *arg)
{
#ifdef FUNC
    printf("==========start read_process_to_msg(%d)==========\n", getpid());
#endif
    /* 1. 读http头 */
    int  pr;
    int  len;
    int  ret;
    int  encd;
    short port;
    int  direction;
    int  len_limit = LEN_SSL_REC;
    char *gunzip = NULL;
    char *before_ip;
    char host[LEN_HOST] = {0};
    char buff_header[LEN_HEADER] = {0};
    unsigned int  len_gunzip = 0;
    PCRE2_SPTR new_body;

    //ret = read_double_crlf(arg->ssl, buff_header, sizeof(buff_header) - 1);
    ret = read_double_crlf(arg->fd, buff_header, sizeof(buff_header) - 1);
    if(ret <= 0) {
#ifdef DEBUG
        printf("cannot read_double_crlf\n");
#endif
        return ret;
    }

    /* 2. 解析http头 */
    http_header_t *header = (http_header_t *)malloc(sizeof(http_header_t));
    memset(header, 0, sizeof(http_header_t));
    init_list_head(&(header->head));

    if(parse_http_header(buff_header, header) < 0) {
#ifdef DEBUG
        printf("cannot parse_http_header(%s)\n", buff_header);
#endif
        return -1;
    }

    /* 3. 获取host:port和before_ip */
    direction = is_http_req_rsp(header);
    if(direction == IS_REQUEST) {
        get_host_port(header, host, &port);  //替换前的ip
        before_ip = get_ip_before_remap(remap_table, host);
#ifdef DEBUG
        printf("is request\n");
        printf("get_host_port = %s:%d\n", host, port);
        printf("before_ip is %s\n", before_ip);
#endif
        if(before_ip == NULL) {
            re = ge_re;
        }
        else {
            if(regex_table == NULL || ((re = get_re_by_host_port(regex_table, before_ip, port)) == NULL)) {
                re = ge_re;
            }
        }
    }

    /* 4. 唤醒handle_server */
    if(1 == wake && direction == IS_REQUEST) {
        wake = 0;
        msg_t msg = {0};
        sprintf((char *)(msg.data), "%s:%d", before_ip, port);
        msg.type = MSG_HOST;
        msg.len   = strlen(msg.data);
        msgsnd(arg->msgid, &msg, sizeof(msg_t) - sizeof(long), 0);
    }

    /* 5. 替换http头 */
    replace_http_header(header, re);
    //方案2性能更好，但不灵活，全替换
    //目前遇到的情况来看，可以使用全替换

    /* 6. 解析优先级，编码，长度信息 */
    len = get_pr_encd(&(header->head), &pr, &encd);

#ifdef DEBUG
    switch(pr) {
        case 0:
            printf("len = %d, PR_NONE,         encd = %d\n", len, encd);
            break;
        case 1:
            printf("len = %d, PR_TXT_CHUNK,    encd = %d\n", len, encd);
            break;
        case 2:
            printf("len = %d, PR_TXT_LEN,      encd = %d\n", len, encd);
            break;
        case 3:
            printf("len = %d, PR_NONE_TXT_LEN, encd = %d\n", len, encd);
            break;
        case 4:
            printf("len = %d, PR_NONE_TXT_CHK, encd = %d\n", len, encd);
            break;
        case 5:
            printf("len = %d, PR_TXT_NONE, encd = %d\n", len, encd);
            break;
        case 6:
            printf("len = %d, PR_Np NE_TXT_NONE, encd = %d\n", len, encd);
            break;
        default:
            break;
    }
    printf("len = %d, pr = %d, encd = %d\n", len, pr, encd);
    if(IS_REQUEST == direction) {
        printf("read is_request\n");
    }
    else if(IS_RESPONSE == direction) {
        printf("read is_response\n");
    }
#endif
    memset(buff_header, 0, sizeof(buff_header));
    /* 7. 根据优先级替换转发 */
    switch(pr) {
        case PR_TXT_LEN:
        {
#ifdef DEBUG
            printf("%d case %d:\n", getpid(), PR_TXT_LEN);
#endif
            /* read body */
            if(len <= 0) {
                /* post header */
                http_header_tostr(header, buff_header);
                write_to_msg(arg, len_limit, "ld", strlen(buff_header), buff_header);
                break;
            }

            unsigned char *buf_body = (unsigned char *)malloc(len + 1);
            if(NULL == buf_body) {
                err_quit("malloc buf_body");
            }
            memset(buf_body, 0, len + 1);

            //int n = readn(arg->ssl, buf_body, len);
            int n = readn(arg->fd, buf_body, len);
#ifdef DEBUG
            printf("pr_txt_len: len = %d, read = %d\n", len, n);
#endif

            if(n < 0) {
#ifdef DEBUG
                printf("PR_CONTENT_LEN: read err\n");
#endif
                free_http_header(&header);
                return -1;
            }
            if(n == 0) {
                free_http_header(&header);
                return 0;
            }
            /* replace content */
            /* change content_length */
            /* send http header and body to handle_server */
            /*
             * 压缩
             *      解压成功
             *          替换成功：修改header(Content-length=new_body, Content-encoding)
             *          替换失败：修改header(Content-length=gunzip  , Content-encoding)
             erase_
             *      解压失败
             *          不修改header
             * 未压缩
             *      替换成功：修改header(Content-length)
             *      替换失败：不修改header
             */
            if(encd == ENCD_NONE) {
                /* 网页未压缩 */
                new_body = replace_content_default_m((char *)buf_body, direction, re);
                if(NULL == new_body) {
                    http_header_tostr(header, buff_header);
                    write_to_msg(arg, len_limit, "ldld", strlen(buff_header), buff_header, n, buf_body);
                }
                else {
                    rewrite_clen_encd(&(header->head), strlen((char *)new_body), GZIP2GZIP);
                    http_header_tostr(header, buff_header);
                    write_to_msg(arg, len_limit, "ldld", strlen(buff_header), buff_header, strlen((char *)new_body), new_body);
                }
            }

            else {
                /* 网页压缩,获取解压内容 */
                ret = -1;
                ret = get_gunzip(buf_body, n, &gunzip, &len_gunzip);
                if(ret == 0){
                    /* 解压成功 */
                    new_body = replace_content_default_m((char *) gunzip, direction, re);
                    if(NULL == new_body) {
                        /* 没有替换,发送原来的压缩数据 */
                        http_header_tostr(header, buff_header);
                        write_to_msg(arg, len_limit, "ldld", strlen(buff_header), buff_header, n, buf_body);
                    }
                    else {
                        /* 替换成功，发送解压并替换后的包 */
                        rewrite_clen_encd(&(header->head), strlen((char *)new_body), GZIP2FLATE);
                        http_header_tostr(header, buff_header);
                        write_to_msg(arg, len_limit, "ldld", strlen(buff_header), buff_header, strlen((char *)new_body), new_body);
                    }
                }
                else if(ret != 0 && encd == ENCD_GZIP) {
                    /* 解压失败 */
                    http_header_tostr(header, buff_header);
                    write_to_msg(arg, len_limit, "ldld", strlen(buff_header), buff_header, n, buf_body);
                }
            }
            SAFE_FREE(gunzip);
            SAFE_FREE(new_body);
            SAFE_FREE(buf_body);
            break;
        }
        case PR_TXT_CHUNK:
        {
#ifdef DEBUG
            printf("%d case %d:\n", getpid(), PR_TXT_CHUNK);
#endif
            /* send header to handle_client */
            /* loop: read, replace and send to handle_server */
            if(encd == ENCD_FLATE)
            {
                /* 未压缩 */
                http_header_tostr(header, buff_header);
                write_to_msg(arg, len_limit, "ld", strlen(buff_header), buff_header);
                forward_http_chunked(arg, len_limit, encd, direction, re);
            }
            else if(encd == ENCD_GZIP)
            {
                /* 压缩 */
                int    m = -1;
                char   chunk_size[64] = {0};
                unsigned int len_chunk  = 0;
                unsigned char *all_chunk = NULL;
                //m = get_all_chunk_m(arg->ssl, &all_chunk, &len_chunk);
                m = get_all_chunk_m(arg->fd, &all_chunk, &len_chunk);
                if(m != 0)
                {
#ifdef DEBUG
                    printf("get_all_chunk failed\n");
#endif
                    break;
                }
                ret = -1;
                ret = get_gunzip(all_chunk, len_chunk, &gunzip, &len_gunzip);
                if(ret == 0)
                {
                    /* 解压成功 */
                    rewrite_c_encd(&(header->head), ENCD_FLATE);
                    new_body = replace_content_default_m(gunzip, direction, re);
                    if(new_body)
                    {
                        /* 替换成功 */
                        sprintf(chunk_size, "%x\r\n", strlen((char *)new_body));
                        http_header_tostr(header, buff_header);
                        write_to_msg(arg, len_limit, "ldldldld",
                                strlen(buff_header), buff_header,
                                strlen(chunk_size), chunk_size,
                                strlen((char *)new_body), new_body,
                                7, "\r\n0\r\n\r\n");
                        SAFE_FREE(new_body);
                    }
                    else
                    {
                        /* 未替换 */
                        sprintf(chunk_size, "%x\r\n", len_gunzip);
                        http_header_tostr(header, buff_header);
                        write_to_msg(arg, len_limit, "ldldldld",
                                strlen(buff_header), buff_header,
                                strlen(chunk_size), chunk_size,
                                len_gunzip, gunzip,
                                7, "\r\n0\r\n\r\n");
                    }
                }
                else
                {
                    /* 解压失败 */
                    sprintf(chunk_size, "%x\r\n", len_chunk);
                    http_header_tostr(header, buff_header);
                    write_to_msg(arg, len_limit, "ldldldld",
                            strlen(buff_header), buff_header,
                            strlen(chunk_size), chunk_size,
                            len_chunk, all_chunk,
                            7, "\r\n0\r\n\r\n");
                }
                SAFE_FREE(gunzip);
                SAFE_FREE(all_chunk);
            }
            break;
        }

        case PR_NONE_TXT_LEN:
        {
#ifdef DEBUG
            printf("%d case %d:\n", getpid(), PR_NONE_TXT_LEN);
#endif
            http_header_tostr(header, buff_header);
            write_to_msg(arg, len_limit, "ld", strlen(buff_header), buff_header);
            printf("pr_none_txt_len: len = %d\n", len);
            if(len <= 0) {
                break;
            }

            ret = read_forward_none_txt(arg, len_limit, len, "pr_none_txt_len");
            if(ret <= 0) {
                free_http_header(&header);
                return ret;
            }
            break;
        }
        case PR_NONE_TXT_CHK:
        {
#ifdef DEBUG
            printf("%d case %d:\n", getpid(), PR_NONE_TXT_CHK);
#endif
            int ava;
            int tot;
            int left;
            int rd;
            int real_read;
            unsigned int size;
            char crlf[2] = {0};
            char chunk_size[64] = {0};
            http_header_tostr(header, buff_header);
            write_to_msg(arg, len_limit, "ld", strlen(buff_header), buff_header);
            /* 循环转发chunk */
            while(1) {
                //read_line(arg->ssl, chunk_size, sizeof(chunk_size));
                read_line(arg->fd, chunk_size, sizeof(chunk_size));
                write_to_msg(arg, len_limit, "ld", strlen(chunk_size), chunk_size);
                erase_nhex(chunk_size);
                hex2dec(chunk_size, &size);
#ifdef DEBUG
                printf("chunk_size = %d\n", size);
#endif
                tot  = 0;
                ava  = len_limit;
                left = size + 2;  //2 is for "\r\n", NUM1\r\nBODY1\r\nNUM2\r\nBODY2\r\n 0\r\n\r\n

                ret = read_forward_none_txt(arg, len_limit, left, "pr_none_txt_chk");
                if(ret <= 0) {
                    free_http_header(&header);
                    return ret;
                }
                if(size == 0) {
                    break;
                }
            }
            break;
        }

        case PR_TXT_NONE:
        {
#ifdef DEBUG
            printf("%d case %d: pr_txt_none\n", getpid(), PR_TXT_NONE);
#endif
            /* handle: 对端发送完最后一个报文后关闭写，不管是request还是response */
            /* 可能有body, 全部接收，替换转发 */
            int  ava;
            int  whole;
            int  offset;
            int  real_read;
            char body[LEN_BODY] = {0};
            whole = 1;
            offset = 0;
            ava = LEN_BODY;
#ifdef DEBUG
            printf("%d case %d: pr_txt_none, will in while loop\n", getpid(), PR_TXT_NONE);
#endif
            while(1) {
                //real_read = SSL_read(arg->ssl, body + offset, ava);
                real_read = read(arg->fd, body + offset, ava);
                if(real_read < 0) {
                    //perror("SSL_read");
                    perror("read");
                    free_http_header(&header);
#ifdef DEBUG
                    printf("%d case %d: pr_txt_none, will return -1\n", getpid(), PR_TXT_NONE);
#endif
                    return -1;
                }
                else if(real_read == 0) {
                    //先替换转发，然后再return.
                    if(offset > 0) {
                        forward_txt(header, body, offset, whole, encd, arg, len_limit, direction, re);
                    }
                    free_http_header(&header);
#ifdef DEBUG
                    printf("%d case %d: pr_txt_none, will return 0, offset = %d\n", getpid(), PR_TXT_NONE, offset);
#endif
                    return 0;
                }
                else {
                    ava    -= real_read;
                    offset += real_read;
                    if(ava == 0) {
                        offset = 0;
                        ava = LEN_BODY;
                        if(whole == 1) {
                            http_header_tostr(header, buff_header);
                            write_to_msg(arg, len_limit, "ld", strlen(buff_header), buff_header);
                        }
                        whole = 0;
                        forward_txt(header, body, offset, whole, encd, arg, len_limit, direction, re);
                        memset(body, 0, sizeof(body));  //unnecessary
                    }
                }
            }
#ifdef DEBUG
            printf("%d case %d: pr_txt_none, will break\n", getpid(), PR_TXT_NONE);
#endif
            break;
        }

        case PR_NONE_TXT_NONE:
        {
#ifdef DEBUG
            printf("%d case %d: pr_none_txt_none\n", getpid(), PR_NONE_TXT_NONE);
#endif
            /* handle: 对端发送完最后一个报文后关闭写，不管是request还是response */
            http_header_tostr(header, buff_header);
            write_to_msg(arg, len_limit, "ld", strlen(buff_header), buff_header);
            //free_http_header(&header);
            if(IS_REQUEST == direction) {
#ifdef DEBUG
                printf("PR_NONE_TXT_NONE: is_request\n");
#endif
                break;
            }
            else if(IS_RESPONSE == direction) {
#ifdef DEBUG
                printf("PR_NONE_TXT_NONE: is_response\n");
#endif
            }
            /* 可能有body,接收转发,长度未知 */
            while((ret = read_forward_none_txt(arg, len_limit, len_limit, "pr_none_txt_none")) == 1) ;
            if(ret <= 0) {
                free_http_header(&header);
                return ret;
            }
            break;
        }

        case PR_NONE:
        default:
        {
#ifdef DEBUG
            printf("%d case %d: pr_none\n", getpid(), pr);
#endif
            http_header_tostr(header, buff_header);
            write_to_msg(arg, len_limit, "ld", strlen(buff_header), buff_header);
            break;
        }
    }
    free_http_header(&header);
#ifdef FUNC
    printf("==========finish read_process_to_msg(%d)==========\n", getpid());
#endif
    return 1;
}

/* 后期优化: 使用链表处理 */
//int get_all_chunk_m(SSL *ssl, unsigned char **all_chunk, unsigned int *len)
int get_all_chunk_m(int fd, unsigned char **all_chunk, unsigned int *len)
{
#ifdef FUNC
    printf("==========start get_all_chunk_m()==========\n");
#endif
    int    n = 0;
    char   crlf[2];
    char   s_size[64] = {0};
    unsigned int size = 0;
    unsigned int tot = 0;
    unsigned char *data = (unsigned char *)calloc(1, 1);
    unsigned char *tmp  = NULL;
    while(1)
    {
        //if((n = read_line(ssl, s_size, sizeof(s_size))) <= 0)
        if((n = read_line(fd, s_size, sizeof(s_size))) <= 0)
            return -1;
#ifdef DEBUG
        printf("[0x%s]\n", s_size);
#endif
        erase_nhex(s_size);
        hex2dec(s_size, &size);
        memset(s_size, 0, sizeof(s_size));
        if(size > 0)
        {
            tmp = (unsigned char *)calloc(1, tot + size);
            memcpy(tmp, data, tot);
            SAFE_FREE(data);
            data = tmp; 
            /* read data and \r\n */
            //readn(ssl, data + tot, size);
            //readn(ssl, crlf, 2);
            readn(fd, data + tot, size);
            readn(fd, crlf, 2);
            tot += size;
#ifdef DEBUG
            printf("get_all_chunk tot=%d\n", tot);
#endif
        }
        else if(size == 0) {
            /* no data but has \r\n */
            //n = readn(ssl, crlf, 2);
            n = readn(fd, crlf, 2);
            break;
        }
    }
    *all_chunk = data;
    *len = tot;
#ifdef FUNC
    printf("==========finish get_all_chunk_m()==========\n");
#endif
    return 0;
}

/*
 * 优化方案已经想好，接口名无需修改，暂不优化，先调通程序
 */
int forward_http_chunked(thread_arg_t *arg, int len_limit, int encd, int direction, pcre2_code *re)
{
    /* 思路：开个大buff接收，满则替换转发，未满则接续接收 */
    /* 此函数只用于转发未压缩的chunked文本http报文 */
#ifdef FUNC
    printf("==========start forward_http_chunked()==========\n");
#endif
    char s_size[64] = {0};
    uint32_t size = 0;
    uint32_t n, m;
    char buff[LEN_CHUNK];
    char *ptr = buff;
    /* size_t tot_buf = 0; */
    int left = sizeof(buff);
    int size_flag = 1;
    while(encd == ENCD_FLATE)
    {
        if(size_flag)
        {
            //if((n = read_line(arg->ssl, s_size, sizeof(s_size))) <= 0)
            if((n = read_line(arg->fd, s_size, sizeof(s_size))) <= 0)
                break;
#ifdef DEBUG
            printf("[0x%s]\n", s_size);
#endif
            erase_nhex(s_size);
            hex2dec(s_size, &size);
#ifdef DEBUG
            printf("read chunked size = %d\n", size);
#endif
        }
        /* chunk_data + "\r\n" */
        /* BUG: 第一次size > LEN_CHUNK, 会造成死循环 */
        if(size + 2 <= left && size > 0)
        {
            //if((n = readn(arg->ssl, ptr, size + 2)) > 0)
            if((n = readn(arg->fd, ptr, size + 2)) > 0)
            {
#ifdef DEBUG
                printf("n=%d\n", n);
#endif
                ptr += (n - 2);
                left -= (n - 2);
                size_flag = 1;  /* 读完chunked正文后,肯定要读取一下chunked的size */
            }
            else
            {
                /* 出错处理:缓冲区中可能有数据，需要将其转发掉，然后退出循环 */
                size_flag = 0;
                size = 0;
            }
        }
        else
        {
            size_flag = 0;
            /* 替换转发 */
            char chunk_size[64] = {0};
            PCRE2_SPTR new_chunked = replace_content_default_m(buff, direction, re);
            if(new_chunked)
            {
                int new_size = strlen((char *) new_chunked);
                sprintf(chunk_size, "%x\r\n", new_size);
#ifdef DEBUG
                printf("\033[33m");
                printf("replace, new chunked size=%s\n", chunk_size);
                printf("\033[0m");
#endif
                write_to_msg(arg, len_limit, "ldldld", strlen(chunk_size), chunk_size, strlen((char *)new_chunked), new_chunked, 2, "\r\n");
                SAFE_FREE(new_chunked);
            }
            else
            {
                sprintf(chunk_size, "%x\r\n", LEN_CHUNK - left);
#ifdef DEBUG
                printf("\033[33m");
                printf("no replace, new chunked size=%s\n", chunk_size);
                printf("\033[0m");
#endif
                write_to_msg(arg, len_limit, "ldldld", strlen(chunk_size), chunk_size, (LEN_CHUNK - left), buff, 2, "\r\n");
            }
            /* 一次替换转发结束 */
            memset(buff, 0, sizeof(buff));
            left = sizeof(buff);
            ptr = buff;
            if(size == 0)
                break;
        }
    }

    write_to_msg(arg, len_limit, "ldld", 5, "0\r\n\r\n");
    /* 转发chunk后的拖挂内容 一般是补充的域(field)信息
     * 如果包含拖挂内容,拖挂内容的长度是无法确定的,Keep-alive就会引起问题,这里:舍弃拖挂内容
     while((n = read(s_fd, buff, sizeof(buff))) > 0)
     m = write(c_fd, buff, n);
     */
#ifdef FUNC
    printf("==========finish forward_http_chunked()==========\n");
#endif
    return 0;
}

int forward_txt(http_header_t *header, unsigned char *body, int len, int whole, int encd, thread_arg_t *arg, int len_limit, int direction, pcre2_code *re)
{
#ifdef FUNC
    printf("==========start forward_txt()==========\n");
#endif
    int ret;
    char *gunzip;
    int len_gunzip;
    char buff_header[LEN_HEADER] = {0};
    PCRE2_SPTR new_body = NULL;
    int df;
#ifdef DEBUG
    printf("len = %d, whole = %d, encd = %d\n", len, whole, encd);
#endif

    /* 不完整的包不用转header */
    if(whole != 1) {
        /*  不完整的压缩包，直接转 */
        if(encd == ENCD_GZIP) {
#ifdef DEBUG
            printf("not whole, direct forwrad, gunzip\n");
#endif
            write_to_msg(arg, len_limit, "ld", len, body);
        }
        else {
            new_body = replace_content_default_m(body, direction, re);
            if(new_body) {
#ifdef DEBUG
                printf("not whole, forward replace\n");
#endif
                write_to_msg(arg, len_limit, "ld", strlen((char *)new_body), new_body);
                SAFE_FREE(new_body);
            }
            else {
#ifdef DEBUG
                printf("not whole, direct forwrad txt no replace\n");
#endif
                write_to_msg(arg, len_limit, "ld", len, body);
            }
        }
    }

    /* 完整的包还要转一下header */
    else {
        if(encd == ENCD_GZIP) {
            /* 整包就解压 */
            ret = get_gunzip(body, len, &gunzip, &len_gunzip);
            if(ret < 0) {
#ifdef DEBUG
                printf("whole, direct forwrad, cannot gunzip\n");
#endif
                http_header_tostr(header, buff_header);
                write_to_msg(arg, len_limit, "ldld", strlen(buff_header), buff_header, len, body); 
            }
            else {
                /* need to rewrite_encd */
                new_body = replace_content_default_m(gunzip, direction, re);
                if(new_body) {
#ifdef DEBUG
                    printf("whole, forward new_body");
#endif
                    rewrite_c_encd(&(header->head), ENCD_FLATE);
                    http_header_tostr(header, buff_header);
                    write_to_msg(arg, len_limit, "ldld", strlen(buff_header), buff_header, strlen((char *)new_body), new_body);
                }
                else 
#ifdef DEBUG
                    printf("whole, direct forwrad, cannot replace\n");
#endif
                http_header_tostr(header, buff_header);
                write_to_msg(arg, len_limit, "ldld", strlen(buff_header), buff_header, len, body); 
            }
            SAFE_FREE(gunzip);
            SAFE_FREE(new_body);
        }

        else {
            http_header_tostr(header, buff_header);
            new_body = replace_content_default_m(body, direction, re);
            if(new_body) {
#ifdef DEBUG
                printf("whole, forward new_body");
#endif
                write_to_msg(arg, len_limit, "ldld", strlen(buff_header), buff_header, strlen((char *)new_body), new_body);
                SAFE_FREE(new_body);
            }
            else {
#ifdef DEBUG
                printf("whole, direct forwrad, cannot replace\n");
#endif
                write_to_msg(arg, len_limit, "ldld", strlen(buff_header), buff_header, len, body);
            }
        }
    }

#ifdef FUNC
    printf("==========finish forward_txt()==========\n");
#endif
    return 1;
}

/* 
 * return :
 *      1 : 读并转发完成
 *      0 : 读到结束,(非信号打断错误) 
 *      -1: 读到错误 
 */
int read_forward_none_txt(thread_arg_t *arg, int len_limit, int len_body, const char *comment)
{
#ifdef FUNC
    printf("==========start read_forward_none_txt==========\n");
#endif
    int tot;
    int ava;
    int left;
    int rd;
    int real_read;
    msg_t msg;
    tot = 0;
    ava = len_limit;
    left = len_body;
#ifdef DEBUG
    printf("%s: read_forward_none_txt: len_body = %d\n", comment, len_body);
#endif
    /* 直接读进共 */
    while(left > 0) {
        rd = left<=ava?left:ava;
        //real_read = SSL_read(arg->ssl, msg.data + tot, rd); 
        real_read = read(arg->fd, msg.data + tot, rd); 
#ifdef DEBUG
        printf("%s: read_forward_none_txt: real_read = %d\n", comment, real_read);
#endif
        if(real_read < 0) {
            //perror("SSL_read()");
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
            tot    += real_read;
            left   -= real_read;
            ava    -= real_read;

            if(ava == 0) {
#ifdef DEBUG
                printf("%s: read_forward_none_txt: tot = %d, still has left\n", comment, tot);
#endif
                msg.len  = tot;
                msg.type = arg->msg_type;
                msgsnd(arg->msgid, &msg, sizeof(msg_t) - sizeof(long), 0);
                tot = 0;
                ava = len_limit;
            }
        }
    }
    msg.len  = tot; 
    msg.type = arg->msg_type;
    msgsnd(arg->msgid, &msg, sizeof(msg_t) - sizeof(long), 0);
#ifdef DEBUG
    printf("%s: tot = %d, no left\n", comment, tot);
#endif

#ifdef FUNC
    printf("==========finish read_forward_none_txt==========\n");
#endif
    return real_read;
}


int create_proxy_server(char *host, short l_port, int listen_num)
{
#ifdef FUNC
    printf("==========start create_proxy_server()==========\n");
#endif
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0)
        err_quit("socket");
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));

    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(l_port);
    if(NULL == host) {
        local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } 
    inet_pton(AF_INET, host, &local_addr.sin_addr.s_addr);
    if(bind(fd, (struct sockaddr *) &local_addr, sizeof(local_addr)) < 0)
        err_quit("bind");
    if(listen(fd, listen_num) < 0)
        err_quit("listen");
#ifdef FUNC
    printf("==========finish create_proxyy_server()==========\n");
#endif
    return fd;
}

int create_real_server(const char *host, short port)
{
    /* 建立和服务器的连接, 使用select超时连接 */
#ifdef FUNC
    printf("==========start create_real_server()==========\n");
#endif
#ifdef DEBUG
    printf("create_real_server host=%s, port=%d\n", host, port);
#endif
    int s_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(s_fd < 0)
        err_quit("socket");
    struct sockaddr_in server_addr;
    struct hostent *server;
    if((server = gethostbyname(host)) == NULL)
    {
#ifdef DEBUG
        printf("\033[31m");
        printf("gethostbyname %s error, h_error=%d, %s\n", host, h_errno, hstrerror(h_errno));
        printf("\033[0m");
#endif
        return -1;
    }
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    //inet_pton(AF_INET, host, &(server_addr.sin_addr.s_addr));
    memcpy(&(server_addr.sin_addr.s_addr), server->h_addr, server->h_length);
    char ip[LEN_IP] = {0};
    if(connect(s_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0)
        err_quit("connect");
#ifdef DEBUG
    printf("%s  %s port=%d\n", host, inet_ntop(AF_INET, server->h_addr, ip, sizeof(ip)), port);
    printf("connected to %s:%d\n", host, port);
#endif
#ifdef FUNC
    printf("==========finish create_real_server()==========\n");
#endif
    return s_fd;
}

int create_real_server_nonblock(const char *host, short port, int sec)
{
    /* 建立和服务器的连接 */
#ifdef FUNC
    printf("==========start create_real_server_nonblock()==========\n");
#endif
    int s_fd = socket(AF_INET, SOCK_STREAM, 0);

    if(s_fd < 0)
        err_quit("socket");
    /* 设置非阻塞 */
    int flags = fcntl(s_fd, F_GETFL, 0);
    if(flags < 0)
    {
        perror("fcntl f_get");
        goto end;
    }
    if(fcntl(s_fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        perror("fcntl f_set");
        goto end;
    }

    struct sockaddr_in server_addr;
    struct hostent *server;
    if((server = gethostbyname(host)) == NULL)
    {
        printf("\033[31m");
        printf("gethostbyname [%s] error, h_error=%d, %s\n", host, h_errno, hstrerror(h_errno));
        printf("\033[0m");
        goto end;
    }
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    /* inet_pton(AF_INET, host, &(server_addr.sin_addr.s_addr)); */
    memcpy(&(server_addr.sin_addr.s_addr), server->h_addr, server->h_length);
    char ip[16] = {0};
#ifdef DEBUG
    printf("%s <--> %s port=%d\n", host, inet_ntop(AF_INET, server->h_addr, ip, sizeof(ip)), port);
#endif
    if(connect(s_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0)
    {
        if(errno != EINPROGRESS)
        {
#ifdef DEBUG
            printf("connect err\n");
#endif
            goto end;
        }
    }
    fd_set rset, wset;
    FD_ZERO(&rset);
    FD_ZERO(&wset);
    FD_SET(s_fd, &rset);
    FD_SET(s_fd, &wset);
    struct timeval tout;
    tout.tv_sec = sec > 0 ? sec : 0;
    tout.tv_usec = 0;
    int ret = select(s_fd + 1, &rset, &wset, NULL, tout.tv_sec > 0 ? &tout : NULL);
    if(ret > 0)
    {
        if(FD_ISSET(s_fd, &rset) || FD_ISSET(s_fd, &wset))
        {
            int error = 0;
            unsigned int len = sizeof(error);
            if(getsockopt(s_fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
            {
                perror("getsockopt");
                goto end;
            }
            else
            {
                /* 改回非阻塞 */
                if(fcntl(s_fd, F_SETFL, flags) < 0)
                    goto end;
                return s_fd;
            }
        }
    }
    else if(ret == 0)
    {
#ifdef DEBUG
        printf("select timeout!\n");
#endif
        goto end;
    }
    else
    {
        perror("select");
        goto end;
    }

end:
    close(s_fd);
#ifdef FUNC
    printf("==========finish create_real_server_nonblock()==========\n");
#endif
    return -1;
}



PCRE2_SPTR replace_content_default_m(char *old, int direction, pcre2_code *re)
{
#ifdef FUNC
    printf("==========start replace_content_default_m()==========\n");
#endif
    PCRE2_SPTR new;
    struct list_head *head = get_list_substring_compiled_code((PCRE2_SPTR) old, re);
    if(head == NULL)
        return NULL;
    if(direction == REQUEST)
        pad_list_rplstr_malloc(head, pad_list_rplstr_remap_table_req_m, remap_table);
    else if(direction == RESPONSE)
        pad_list_rplstr_malloc(head, pad_list_rplstr_remap_table_rsp_m, remap_table);
    /* pad_list_rplstr_malloc(head, pad_list_rplstr_remap_table_rsp_m, remap_table); */
    new = replace_all_default_malloc((PCRE2_SPTR) old, head);
    free_list_substring(&head);
#ifdef FUNC
    printf("==========finish replace_content_default_m（）==========\n");
#endif
    if(NULL == new)
        return NULL;
    return new;
}


int rewrite_url(char *url, pcre2_code *re)
{
    /* 替换ip */
#ifdef FUNC
    printf("==========start rewrite_url()==========\n");
#endif
    int len;
    PCRE2_SPTR subject = replace_content_default_m(url, IS_REQUEST, re);
    if(subject)
    {
        len = strlen((char *)subject);
        memmove(url, (char *)subject, strlen((char *)subject));
        *(url + len) = '\0';
        SAFE_FREE(subject);
    }

    /* 重写格式 */
    char *p = strstr(url, "http://");
    if(p)
    {
        char *p1 = strchr(p + 7, '/');
        if(p1)
        {
            /* http://192.168.1.33/setup.cgi?ip1=192.168.1.33&ip2=192.168.1.22  --> /setup.cgi?ip1=192.168.1.33&ip2=192.168.1.22 */
            len = strlen(p1);
            memmove(url, p1, strlen(p1));
            *(url + len) = '\0';
        }
        else
        {
            /* http://192.168.1.33 --> / */
            memset(url, 0, LEN_URL);
            strcpy(url, "/");
        }
    }
    //printf("after rewrite url=%s\n", req->url);
#ifdef FUNC
    printf("==========finish rewrite_url()==========\n");
#endif
    return 0;
}


int replace_field(char *field_value, int direction, pcre2_code *re)
{
#ifdef FUNC
    printf("==========start replace_field()==========\n");
#endif
    PCRE2_SPTR subject = (PCRE2_SPTR) field_value;
    struct list_head *head = get_list_substring_compiled_code(subject, re);
    if(head == NULL)
        return -1;

    if(direction == REQUEST)
        pad_list_rplstr_malloc(head, pad_list_rplstr_remap_table_req_m, remap_table);
    else if(direction == RESPONSE)
        pad_list_rplstr_malloc(head, pad_list_rplstr_remap_table_rsp_m, remap_table);
    PCRE2_SPTR new_subject = replace_all_default_malloc(subject, head);
    if(NULL == new_subject)
    {
        free_list_substring(&head);
        return -1;
    }
    memset(field_value, 0, LEN_FIELD_VALUE);
    strcpy(field_value, (char *) new_subject);
    free_list_substring(&head);
    SAFE_FREE(new_subject);
#ifdef FUNC
    printf("==========finish replace_field()==========\n");
#endif
    return 0;
}

/* 
 * 
 */
//int rewrite_http_header(struct list_head *head, int direction, pcre2_code *re)
int replace_http_header(http_header_t *header, pcre2_code *re)
{
#ifdef FUNC
    printf("==========start replace_http_header()==========\n");
#endif
    int direction = is_http_req_rsp(header);
    /* replace url */
    if(direction == IS_REQUEST) {
        rewrite_url(header->url, re);
    }
    /* 使用get方法时 GET /setup.cgi?ip=192.168.1.1&port=8080提交的表单数据不应该被替换 */
    struct list_head *head = &(header->head);
    struct list_head *pos = NULL;
    list_for_each(pos, head)
    {
        http_field_t *field = list_entry(pos, http_field_t, list);

        if(strcasecmp(field->key, "Host") == 0)
        {
#ifdef DEBUG
            printf("<%s>\n", field->key);
#endif
            replace_field(field->value, direction, re);
        }
        if(strcasecmp(field->key, "Referer") == 0)
        {
#ifdef DEBUG
            printf("<%s>\n", field->key);
#endif
            replace_field(field->value, direction, re);
        }
        if(strcasecmp(field->key, "Origin") == 0)
        {
#ifdef DEBUG
            printf("<%s>\n", field->key);
#endif
            replace_field(field->value, direction, re);
        }
        if(strcasecmp(field->key, "Location") == 0)
        {
#ifdef DEBUG
            printf("<%s>\n", field->key);
#endif
            replace_field(field->value, direction, re);
        }
    }
#ifdef FUNC
    printf("==========finish replace_http_header()==========\n");
#endif
    return 0;
}

int get_gunzip(unsigned char *src, unsigned int len_s, char **dst, unsigned int *len_d)
{
#ifdef FUNC
    printf("==========start get_gunzip==========\n");
#endif
    int ret;
    srandom(time(NULL));
    char tmp[64] = {0};
    char tmp_gz[64] = {0};
    char cmd[256] = {0};
    long r1 = random();
    long r2 = random();
    sprintf(tmp, "/tmp/%ld%ld", r1, r2);
    sprintf(tmp_gz, "%s.gz", tmp);
    int fd_s = open(tmp_gz, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if(fd_s < 0)
        return -1;
    if(write(fd_s, src, len_s) != len_s)
    {
        close(fd_s);
        unlink(tmp_gz);
        return -1;
    }

    close(fd_s);
    sprintf(cmd, "gunzip %s", tmp_gz);                       
    sighandler_t old_handler = signal(SIGCHLD, SIG_DFL);
    ret = system(cmd);
    signal(SIGCHLD, old_handler);
    unlink(tmp_gz);                                          /* not necessary */

    int fd_d = open(tmp, O_RDONLY);
    if(fd_d < 0)
        return -1;
    *len_d = lseek(fd_d, 0, SEEK_END);
    lseek(fd_d, 0, SEEK_SET);
    *dst = (char *)calloc(1, *len_d);
    if(NULL == *dst)
    {
        perror("malloc");
        close(fd_d);
        unlink(tmp); 
        return -1;
    }
    if(read(fd_d, *dst, *len_d) != *len_d)
    {
        SAFE_FREE(*dst);
        close(fd_d);
        unlink(tmp); 
        return -1;
    }
    close(fd_d);
    unlink(tmp);
#ifdef FUNC
    printf("==========finish get_gunzip()==========\n");
#endif
    return 0;
}

/* 信号处理函数 */
void sig_handle(int signo)
{
#ifdef FUNC
    printf("==========start sig_handle()==========\n");
#endif
    if(signo == SIGCHLD){
#ifdef DEBUG
        printf("%d capture SIGCHLD\n", getpid());
#endif
        pid_t pid;
        while((pid = wait(NULL)) > 0)
        {
#ifdef DEBUG
            printf("wait %d\n", pid);
#endif
        }
    }
    else if(signo == SIGPIPE)
    {
#ifdef DEBUG
        printf("%d capture SIGPIPE\n", getpid());
#endif
        exit(1);
    }
    else if(signo == SIGINT)
    {
#ifdef DEBUG
        printf("%d capture SIGINT\n", getpid());
#endif
        exit(1);
    }
#ifdef FUNC
    printf("==========finish sig_handle()==========\n");
#endif
}


void sig_handle_2(int signo)
{
#ifdef FUNC
    printf("==========start sig_handle()==========\n");
#endif
    if(signo == SIGCHLD){
#ifdef DEBUG
        printf("%d capture SIGCHLD\n", getpid());
#endif
        pid_t pid;
        while((pid = wait(NULL)) > 0)
        {
#ifdef DEBUG
            printf("%d wait %d\n", getpid(), pid);
#endif
        }
        /* 还没转发完成就不退出 */
        struct msqid_ds buf;
        if(msgctl(msgid_s, IPC_STAT, &buf) < 0) {
            perror("msgctl IPC_STAT");
            exit(0);
        }
        if(buf.msg_qnum > 0) {
            return;
        }
        goto exit_2;
    }
    else if(signo == SIGPIPE)
    {
#ifdef DEBUG
        printf("%d capture SIGPIPE\n", getpid());
#endif
        goto exit_2;
    }
    else if(signo == SIGINT)
    {
#ifdef DEBUG
        printf("%d capture SIGINT\n", getpid());
#endif
        goto exit_2;
    }
    else if(signo == SIGHUP)
    {
#ifdef DEBUG
        printf("%d capture SIGHUP\n", getpid());
#endif
        goto exit_2;
    }
    else {
        printf("%d capture %s\n", getpid(), signo);
        goto exit_2;
    }
exit_2:
    msg_queue_destory_all(); 
#ifdef DEBUG
    printf("%d exit !\n", getpid());
#endif
    exit(1);
#ifdef FUNC
    printf("==========finish sig_handle_2()==========\n");
#endif
}
int main(int argc, char **argv)
{
    /* 参数检查 */
    if(argc != 2) {
        printf("Usage: %s port      #加端口号启动程序\n", argv[0]);
#ifdef VERSION
        printf("Usage: %s -v        #版本\n", argv[0]);
#endif
        return 0;
    }
#ifdef VERSION
    if(argc == 2 && strcmp("-v", argv[1]) == 0) {
        printf("%s\n", VERSION);
        return 0;
    }
#endif

    /* get_remap_table */
    remap_table = get_remap_table_m("ipmaps");
    if(NULL == remap_table) {
        fprintf(stderr, "get_remap_table_m failed\n");
        syslog(LOG_INFO, "[CONFIG] %s启动失败-获取映射表(get_remap_table)", argv[0]); 
        exit(0);
    }

    /* get_regex_table */
    regex_table = get_regex_table_m("http_devices");

    /* get general_regex */
    ge_re = get_general_regex("general_regex");
    if(ge_re == NULL)
    {
        fprintf(stderr, "h_general_regex is NULL\n");
        syslog(LOG_INFO, "[CONFIG] %s启动失败-必填项:通用正则表达式为空(get_general_regex)", argv[0]); 
        exit(0);
    }
    printf("general_regex exists\n");

    /* get_proxy_config*/

    /* 初始化openssl, ctx_s, ctx_c等 */
    if(ssl_init() < 0) {
        printf("cannot ssl_init()\n");
        return 0;
    }

    /* 建立socket */
    int   l_num = 1024;
    short l_port = 8082;
    char  l_host[] = "0.0.0.0";
    l_fd = create_proxy_server(l_host, l_port, l_num);
    if(l_fd < 0) {
        printf("cannot create proxy server\n");
        return 0;
    }
    /* 监听 */
    switch(fork()) {
        case 0:
            printf("%s在后台启动\n", argv[0]);
            syslog(LOG_INFO, "[CONFIG] %s程序启动", argv[0]); 
            proxy_listen();
            exit(0);
        case -1:
            printf("fork()监听进程失败\n");
            syslog(LOG_INFO, "[CONFIG] %s启动失败-fork failed", argv[0]); 
            err_quit("fork()");
            break;
        default:
            break;
    }
    return 0;
}

int proxy_listen(void)
{
#ifdef FUNC
    printf("==========start proxy_listen(%d)==========\n", getpid());
#endif
    /* 注册信号处理函数 */
    if(signal(SIGPIPE, sig_handle) == SIG_ERR) {
        err_quit("signal()");
    }

    if(signal(SIGINT, sig_handle) == SIG_ERR) {
        err_quit("signal()");
    }
    if(signal(SIGCHLD, sig_handle) == SIG_ERR) {
        err_quit("signal()");
    }

    struct sockaddr_in client_addr;
    bzero(&client_addr, sizeof(client_addr));
    socklen_t len_client = sizeof(client_addr);
    fd_set rset, wset;
    int max_fd = 0;
    while(1) {
        FD_ZERO(&rset);
        FD_ZERO(&wset);
        FD_SET(l_fd, &rset);
        FD_SET(l_fd, &wset);
        max_fd = max_fd>=l_fd?max_fd:l_fd;
        int ret = select(max_fd + 1, &rset, &wset, NULL, NULL);
        if(ret < 0) {
            if(errno == EINTR || errno == EAGAIN) {
                continue;
            }
            perror("select()");         //运行报错:bad file descriptor
            break;
        }
        else if(0 == ret) {
            printf("select timeout\n"); 
            continue;
        }
        else {
            if(FD_ISSET(l_fd, &rset) || FD_ISSET(l_fd, &wset)) {
                c_fd = accept(l_fd, (struct sockaddr *)&client_addr, &len_client);
                if(c_fd < 0) {
                    perror("cannot accept correctly, accept()");
                    continue;
                }

                printf("client online\n");
                switch(fork()) {
                    case -1:
                        close(c_fd);
                        perror("proxy_listen fork()");
                        break;
                    case 0:
                        close(l_fd);
                        handle_client();
                        exit(0);
                    default:
                        close(c_fd);
                        continue;
                }
            }
        }

    }
    //隐式回收
#ifdef FUNC
    printf("==========finish proxy_listen(%d)==========\n", getpid());
#endif
    return 0;
}
