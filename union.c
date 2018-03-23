#include <stdio.h>
#include <stdlib.h>
#include <string.h>


typedef struct {
    int iprange;
    int reverse;
    union {
        char *ipaddr;
        char *iprange;
    }ip;
}ipt_addr_t;

int main() 
{
    char *str = "!192.168.1.1-192.168.1.100";
    ipt_addr_t addr;
    addr.ip.ipaddr = malloc(strlen(str) + 1);
    addr.iprange = strstr(str, "-")?1:0;
    addr.reverse = strstr(str, "!")?1:0;
    strcpy(addr.ip.ipaddr, addr.reverse?strstr(str, "!")+1:str);

    if(addr.iprange) {
        printf("-m iprange%s--src-range %s\n", addr.reverse?" ! ":"" , addr.ip.iprange);
    }
    else {
        printf("%s-s %s\n", addr.reverse?" ! ":"", addr.ip.ipaddr);
    }
    printf("%d\n", strlen("1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31"));
    
    return 0;
}


