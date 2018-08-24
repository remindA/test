#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


int main(int argc, char **argv)
{
    char *str = "   192.168.1.1:8080 niu";
    char *p = str;
    while(*p == ' ') p++;
    printf("[%s]\n", p);
    char *fmt = "%[^:]:%[0-9]";
    char ip[18] = {0};
    char port[7] = {0};
    
    int ret = sscanf(p, fmt, ip, port);
    printf("ret=%d, ip=[%s], port=[%s]\n", ret, ip, port);

    char *s1 = "192.168.1.1\r\n";
    char *s2 = "192.168.1.1 \r\n";
    char *s3 = "192.168.1.1 1\r\n";
    char *s4 = "192.168.1.1 1\n";
    memset(ip, 0, sizeof(ip));
    sscanf(s1, "%[^\r^\n^ ]", ip);
    printf("ip=[%s], strlen(ip)=%d\n", ip, strlen(ip));

    memset(ip, 0, sizeof(ip));
    sscanf(s2, "%[^\r^\n^ ]", ip);
    printf("ip=[%s], strlen(ip)=%d\n", ip, strlen(ip));

    memset(ip, 0, sizeof(ip));
    sscanf(s3, "%[^\r^\n^ ]", ip);
    printf("ip=[%s], strlen(ip)=%d\n", ip, strlen(ip));

    memset(ip, 0, sizeof(ip));
    sscanf(s4, "%[^\r^\n^ ]", ip);
    printf("ip=[%s], strlen(ip)=%d\n", ip, strlen(ip));
    
    char crlf[3] = {0};
    char chunk[10] = {0};
    char *s5 = "1fE\r\n";
    char *s6 = "3Ba\n";
    memset(crlf, 0 ,sizeof(crlf));
    memset(chunk, 0, sizeof(chunk));
    sscanf(s5, "%[0-9a-fA-F]%[\r\n]", chunk, crlf);
    printf("chunk=[%s], strlen(chunk)=%d, crlf=[%s], strlen(crlf)=%d\n", chunk, strlen(chunk), crlf, strlen(crlf));

    memset(crlf, 0 ,sizeof(crlf));
    memset(chunk, 0, sizeof(chunk));
    sscanf(s6, "%[0-9a-fA-f]%[\r\n]", chunk, crlf);
    printf("chunk=[%s], strlen(chunk)=%d, crlf=[%s], strlen(crlf)=%d\n", chunk, strlen(chunk), crlf, strlen(crlf));
    return 0;

}
