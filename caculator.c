#include <stdio.h>
#include <string.h>



int main()
{
    char *str = "tcp,udp,icmp";

    char *comma;
    char *p = str;
    int cnt = 0;
    while((comma = strstr(p, ","))) {
        cnt++;
        p = comma + 1;
    }
    printf("cnt = %d\n", cnt);
    return 0;
}

