#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct ss{
    int num;
    enum{
    ok = 1,
    bad = 2
    } stat;
    union{
        char *ptr;
        int value;
    } u;
    char *tail;
    char ip[16];
    char mac[48];
};

int main()
{
    // 1. struct ss st  ;
    // 2.
    struct ss st = {
        .num = 3,
        .stat = 2,
        .tail = NULL,
        .ip = strstr("192.168.1.1", "192")
    };
    
    printf("num  = %d\n", st.num);
    printf("stat = %d\n", st.stat);
    printf("u    = %d\n", st.u);
    printf("tail = %p\n", st.tail);
    printf("ip = %s\n", st.ip);
    printf("mac = %s\n", st.mac);

    return 0;

}

