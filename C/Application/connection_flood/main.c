/*
 * =====================================================================================
 *
 *       Filename:  main.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年08月14日 11时04分34秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#include "utils_net.h"

void usage()
{
    printf("connection_flood ip port links\n");
}

int main(int argc, char **argv)
{
    if(argc != 4) {
        usage();
        return 0;
    }
    int num = 0;
    char *ip = argv[1];
    unsigned short port = (unsigned short)atoi(argv[2]);
    int tot = atoi(argv[3]);
    int *arr = (int *)calloc(tot, sizeof(int));
    const char *http_get = "GET / HTTP/1.1\r\n";
    while(tot--) {
        arr[tot] = sock_connect(ip, port);
        if(arr[tot] <= 0) {
            printf("Cannot connect to %s:%d\n", ip, port);
        }
        else {
            num++;
            printf("第%d个连接\n", num);
            sock_set_reuseaddr(arr[tot]);
            //write(arr[tot], http_get, strlen(http_get));
            // usleep(100 * 1000);
        }
    }
    while(1) {
        sleep(1);
    }
    printf("end\n");
    return 0;
}
