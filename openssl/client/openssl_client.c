//client.c./


/************关于本文档********************************************
 * *f./ ././ ilename: sockfd-client.c
 * *purpose: 演示利用Opensockfd 库进行基于IP 层的sockfd 加密通讯的方法，这是客户端例子
 * Linux 爱好者Linux 知识传播者SOHO 族开发者最擅长C 语言
 * *date time:2013-11-22
 * *Note: 任何人可以任意复制代码并运用这些文档，当然包括你的商业用途
 * * 但请遵循GPL
 * *********************************************************************/

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "saa_include.h"
#include "client_info.h"

#define MAXBUF 1024
#define ETH_0  "eth0"

void read_service(void *arg);
void err_quit(const char *api);
void sig_register(void);
void sig_handler(int signo);
int read_packet_malloc(int client_fd, unsigned short *ver, unsigned short *flag, unsigned short *len, char**data);
int print_reply_info_from_data_v1(const unsigned short len_data, const char *data);
int send_packet_by_flag(int sock_fd, unsigned short flag);
int construct_data_by_flag_malloc(unsigned short flag, unsigned short *len, char **data);

int sockfd = -1;
int main(int argc, char **argv)
{
    struct sockaddr_in dest;
    char buffer[MAXBUF + 1];

    if (argc != 3) {

        printf("参数格式错误！正确用法,比如: %s 127.0.0.1 80\n"
                "此程序用来从某个IP 地址的服务器某个端口接收最多MAXBUF 个字节的消息\n",
                argv[0]);

        exit(0);
    }

    sig_register();
    /* 创建一个socket 用于tcp 通信*/
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket");
        exit(errno);
    }
    printf("socket created\n");

    /* 初始化服务器端（对方）的地址和端口信息*/
    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(atoi(argv[2]));
    if (inet_aton(argv[1], (struct in_addr *) &dest.sin_addr.s_addr) == 0) {
        perror(argv[1]);
        exit(errno);
    }
    printf("address created\n");

    /* 连接服务器*/
    if (connect(sockfd, (struct sockaddr *) &dest, sizeof(dest)) != 0) {
        perror("Connect ");
        exit(errno);
    }
    printf("server connected\n");


    pthread_t th_read;
    if(pthread_create(&th_read, NULL, (void *)read_service, (void *)&sockfd) != 0)
        perror("create read_service");


    send_packet_by_flag(sockfd, SAA_FLAG_REQUEST);

    while(1)
    {
        sleep(HEARTBEAT_INTERVAL);
        send_packet_by_flag(sockfd, SAA_FLAG_AUTH_STATE);
    }


    close(sockfd);
    return 0;
}


void read_service(void *arg)
{
    int sock_fd = *((int *)arg);
    int retval;
    pthread_t tid = pthread_self();
    pthread_detach(tid);
    printf("in read_service\n");
    s_element ele;
    bzero(&ele, sizeof(s_element));
    while(1)
    {
        unsigned short version;
        unsigned short flag;
        unsigned short len_data;
        char *data = NULL;
        flag = -1;

        int ret = read_packet_malloc(sock_fd, &version, &flag, &len_data, &data);    //记得free
        if(ret == 0)
            break;
        if(ret < 0)
            continue;
        else
        {
            ;
            printf("this packet flag=%2x\n", flag);
            print_reply_info_from_data_v1(len_data, data);
            free(data);
        }
    }

    printf("server may dead,or other situations\n");
    pthread_exit(&retval);
}



void err_quit(const char *api)
{
    perror(api);
    exit(1);
}

void sig_register(void)
{
    if(signal(SIGINT, sig_handler) == SIG_ERR)
        err_quit("signal SIGINT");
    if(signal(SIGPIPE, sig_handler) == SIG_ERR)
        err_quit("signal SIGPIPE");
}

void sig_handler(int signo)
{
    switch(signo)
    {
        case SIGINT:
            printf("capture SIGINT\n\n");
            close(sockfd);
            exit(1);
        case SIGPIPE:
            printf("capture SIGPIPE\n\n");
            close(sockfd);
            exit(1);
        default : break;
    }
}



//PS:接收非char,unsigned char类型数据：字节序转换
/* return:
 *      < 0: read出错\读取字节数不足\头值出错\尾值出错等。
 *      ==0: select超时\客户端发送FIN
 *      > 0: 读取成功，需要free。
 */
int read_packet_malloc(int client_fd, unsigned short *ver, unsigned short *flag, unsigned short *len, char**data)
{
    //使用select实现精确定时
    /*
    struct timeval tv = {TIMEOUT_READ, 0};
    fd_set rset;
    FD_ZERO(&rset);
    FD_SET(client_fd, &rset);   //就设置了这一个fd，如果有可读，肯定时这个fd可读。
    int ret_select = select(client_fd + 1, &rset, NULL, NULL, &tv);
    if(ret_select <= 0)
    {
        if(ret_select < 0)
            perror("select");
        return ret_select;      //超时0，出错-1
    }
    */

    //接受固定长度"头+版本+保留+FLAG+len"
    packet_head_t pk_head;
    int ret = read(client_fd, &pk_head, sizeof(pk_head));
    if(ret != sizeof(pk_head))
    {
        printf("ret!=sizeof(pk_head) %d!=%d\n", ret, sizeof(pk_head));
        return (ret = ret<=0?ret:-1);
    }
    unsigned short head;
    unsigned char  rsrv;
    unsigned short tail;
    head  = ntohs(pk_head.head);
    *ver  = ntohs(pk_head.ver);
    rsrv  = ntohs(pk_head.rsrv);
    *flag = ntohs(pk_head.flag);
    *len  = ntohs(pk_head.len);
    if(SAA_TYPE_HEAD != head)
    {
        printf("wrong head=%2x, abandon packet.\n", head);
        return -1;
    }

    printf("head  = %2x\n", head);
    printf("ver   = %2x\n", *ver);
    printf("rsrv  = %2x\n", rsrv);
    printf("*flag = %2x\n", *flag);
    printf("*len  = %d\n", *len);

    *data = NULL;
    if(*len > 0)
    {

        *data = (char *)malloc(*len);
        if(NULL == *data)
        {
            printf("ret=%d\n", ret);
            perror("malloc");
            return ret;
        }
        ret = read(client_fd, (*data), *len);
        printf("read data %d bytes,  *len=%d\n", ret, *len);
        if(ret != *len)
        {
            free(*data);
            *data = NULL;
            printf("read data wrong.\n");
            return (ret = ret<=0?ret:-1);
        }
    }

    ret = read(client_fd, &tail, sizeof(tail));
    if(ret != sizeof(tail))
    {
        free(*data);
        *data = NULL;
        printf("read tail wrong.\n");
        return (ret = ret<=0?ret:-1);
    }
    tail = ntohs(tail);
    printf("tail=%2x\n", tail);

    if(SAA_TYPE_TAIL != tail)
    {
        free(*data);
        *data = NULL;
        return -1;
    }

    return ret;
}

int print_reply_info_from_data_v1(const unsigned short len_data, const char *data)
{
    if(len_data <= 0)
        return -1;
    printf("data=%s\n", data);
    return 0;
}


//PS:发送非char,unsigned char类型数据：字节序转换
int send_packet_by_flag(int sock_fd, unsigned short flag)
{
    packet_head_t pk_head;
    unsigned short len = 0;
    char *data;
    unsigned short tail;
    int ret = construct_data_by_flag_malloc(flag, &len, &data);
    if(ret < 0)
    {
        printf("Failed: to construct data.\n");
        return -1;
    }

    pk_head.head = htons(SAA_TYPE_HEAD);
    pk_head.ver  = htons(VERSION_1);
    pk_head.rsrv = RESERVE;
    pk_head.flag = htons(flag);
    pk_head.len  = htons(len);
    tail         = htons(SAA_TYPE_TAIL);

    ret = write(sock_fd, (char *)&pk_head, sizeof(pk_head));
    if(ret != sizeof(pk_head))
    {
        printf("write pk_head ret!=sizeof(pk_head) %d!=%d\n", ret, sizeof(pk_head));
        return -1;
    }

    if(len > 0)
    {
        ret = write(sock_fd, (char *)data, len);
        if(ret != len)
        {
            printf("write data ret!=len %d!=%d\n", ret, len);
            free(data);
            data = NULL;
            return -1;
        }
        printf("write data len=%d\n", len);
        free(data);
        data = NULL;
    }

    ret = write(sock_fd, (char *)&tail, sizeof(tail));
    if(ret != sizeof(tail))
    {
        printf("write tail ret!=sizeof(tail) %d!=%d\n", ret, sizeof(tail));
        return -1;
    }

    return 0;
}


int construct_data_by_flag_malloc(unsigned short flag, unsigned short *len, char **data)
{
    switch(flag)
    {
        case SAA_FLAG_REQUEST:
            {
                unsigned char mac[LEN_MAC] = {0};
                char machine_code[17] = "1234567890abcdef";
                int offset = 0;
                int ret = -1;
                ret = get_eth_MAC(ETH_0, mac);
                printf("get mac ret = %d\n", ret);
                *len = LEN_MAC + 16;
                *data = (char *)malloc(*len);
                if(NULL == *data)
                {
                    perror("malloc");
                    return -1;
                }
                offset = 0;
                memcpy(*data + offset, mac, LEN_MAC);
                offset += LEN_MAC;
                memcpy(*data + offset, machine_code, strlen(machine_code));
                break;
            }
            //case SAA_FLAG_REPLY:
        case SAA_FLAG_HEARTBEAT:
            {
                *len = 0;
                break;
            }
        case SAA_FLAG_AUTH_STATE:
            {
                *len = 0;
                break;
            }
            //case SAA_FLAG_ADDR_LIST:
            //case SAA_FLAG_ACCESS_TIME:
        default:
            printf("Construct data: No such flag.\n");
            return -1;   
    }
    return 0;
}
