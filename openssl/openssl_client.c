/*
 * =====================================================================================
 *
 *       Filename:  openssl_client.c
 *
 *    Description:  测试openss客户端连接
 *
 *        Version:  1.0
 *        Created:  2018年01月09日 14时04分06秒
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
#include <sys/mman.h>
#include <sys/stat.h>
#include <semaphore.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include "err_quit.h"

extern int h_errno;    /* #include <netdb.h> */

int print_ssl_error(SSL *ssl, int ret);
int create_real_server(const char *host, short port);

int main(int argc, char **argv)
{
    if(argc != 3) {
        printf("usage: %s host port\n", argv[0]);
        return 0;
    }
    /* ssl初始化 */
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();
    SSL_CTX *ctx = SSL_CTX_new(TLSv1_2_client_method());
    if(!ctx) {
        printf("cannot create ssl_ctx\n");
        return 0;
    }

    //SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);   //验证服务器证书
    //SSL_CTX_set_cipher_list(ctx, "ALL");              //设置支持的加密方法
    //SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

    int fd = create_real_server(argv[1], (short)atoi(argv[2]));
    if(fd < 0) {
        printf("create_read_server err\n");
        return 0;
    }
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);

    int ret = SSL_connect(ssl);
    if(-1 == ret) {
        //printf("cannot create ssl connection\n");
        print_ssl_error(ssl, ret);
        exit(0);
    }
    else {
        printf("create ssl connection\n");
    }

    printf("%s\n", SSL_get_cipher(ssl));

    X509 *server_cert = SSL_get_peer_certificate(ssl);
    if(server_cert) {
        printf("Subject: %s\n", X509_NAME_oneline(X509_get_subject_name(server_cert), NULL, 0));
        printf("issuer : %s\n", X509_NAME_oneline(X509_get_subject_name(server_cert), NULL, 0));
        X509_free(server_cert);
    }
    else {
        printf("服务器没有证书信息\n");
    }
    char *req = "GET / HTTP/1.1\r\n\r\n";
    SSL_write(ssl, req, strlen(req));
    char buff[1024] = {0};
    SSL_read(ssl, buff, sizeof(buff));
    printf("%s\n", buff);

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
        case SSL_ERROR_WANT_ASYNC:
            printf("ssl_error_want_async\n");
            break;
        case SSL_ERROR_WANT_ASYNC_JOB:
            printf("ssl_error_want_async_job\n");
            break;
        case SSL_ERROR_WANT_CLIENT_HELLO_CB:
            printf("ssl_error_want_client_hello_cb\n");
            break;
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

int create_real_server(const char *host, short port)
{
    /* 建立和服务器的连接, 使用select超时连接 */
    //#ifdef DEBUG
    printf("create_real_server host=%s, port=%d\n", host, port);
    //#endif
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
        return -1;
    }
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    //inet_pton(AF_INET, host, &(server_addr.sin_addr.s_addr));
    memcpy(&(server_addr.sin_addr.s_addr), server->h_addr, server->h_length);
    char ip[16] = {0};
    if(connect(s_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0)
        err_quit("connect");
    //#ifdef DEBUG
    printf("%s <--> %s port=%d\n", host, inet_ntop(AF_INET, server->h_addr, ip, sizeof(ip)), port);
    printf("connected to %s:%d\n", host, port);
    printf("==========create_real_server==========\n");
    //#endif

    return s_fd;
}
