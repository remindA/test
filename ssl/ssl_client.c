/*
 * =====================================================================================
 *
 *       Filename:  ssl_client.c
 *
 *    Description:  测试提高ssl连接的速度(session ticket)
 *
 *        Version:  1.0
 *        Created:  2018年01月30日 15时03分38秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

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
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/param.h>
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
SSL_CTX *ctx_c;

int ssl_init(void);
int create_real_server(const char *host, short port);

int main(int argc, char **argv)
{
    if(argc != 3) {
        printf("usage: %s host times\n", argv[0]);
        return 0;
    }

    int   i;
    int   ret;
    char *host = argv[1];
    int   times = atoi(argv[2]);
    struct timeval st;
    struct timeval ed;
    long int *time = (long int *)malloc(sizeof(long int)*times);
    ssl_init();
    SSL_SESSION *tmp = NULL;
    SSL_SESSION *session = NULL;
    for(i = 0; i < times; i++) {
        if(i != 0) 
            sleep(10);
        int fd = create_real_server(host, 443);
        gettimeofday(&st, NULL);
        /* ssl */
        SSL *ssl_c = SSL_new(ctx_c);
        if(NULL == ssl_c) {
            printf("cannot SSL_new\n");
            return 0;
        }
        //printf("SSL_new ok\n");
        if(session) {
            if(SSL_set_session(ssl_c, session) == 0) {
                printf("cannot SSL_set_session\n");
            }
            else {
                printf("SSL_set_session ok\n");
            }
        }
        else {
            printf("session = %p\n", session);
        }
        ret = SSL_set_fd(ssl_c, fd);
        if(ret != 1) {
            printf("cannot SSL_set_fd\n");
            return 0;
        }
        //printf("SSL_set_fd ok\n");
        if((ret = SSL_connect(ssl_c)) == 0) {
            printf("cannot SSL_connect\n");
            return 0;
        }
        //printf("SSL_connect ok\n");
        if(session == NULL) {
            if((tmp = SSL_get_session(ssl_c))) {
                printf("get session\n");
                session = SSL_SESSION_dup(tmp);
                if(session) {
                    printf("session dup ok, timeout = %ld\n", SSL_SESSION_get_timeout(session));
                }
                else {
                    printf("cannot session dup\n");
                }
            }
        }
        gettimeofday(&ed, NULL);
        time[i] = (ed.tv_sec-st.tv_sec)*1000 + (ed.tv_usec-st.tv_usec)/1000;
        SSL_shutdown(ssl_c);
        SSL_free(ssl_c);
        shutdown(fd, SHUT_RDWR);
    }
    SSL_SESSION_free(session);
    int total = 0;
    for(i = 0; i < times; i++) {
        printf("try %d, ssl connet\t%ldms\n", i+1, time[i]);
        total += time[i];
    }
    printf("try  avarage      \t%ldms\n", total/times);
    return 0;
}


int ssl_init(void)
{ 
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    ctx_c = SSL_CTX_new(TLSv1_client_method());  //代理客户端
    if(!ctx_c) {
        printf("cannot create ctx_c\n");
        return -1;
    }
    return 0;
}


int create_real_server(const char *host, short port)
{
    /* 建立和服务器的连接, 使用select超时连接 */
    int s_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(s_fd < 0) {
        perror("socket()");
        return -1;
    }
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(host);

    if(connect(s_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        return -1;
    }
    printf("connected to %s:%d\n", host, port);
    return s_fd;
}
