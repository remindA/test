#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>

int main()
{
    unsigned char  type = 0x12;
    unsigned short length = strlen("hello") + 1;
    char value[] = "hello";

    unsigned short len = htons(length);
    printf("type=%x, htons(type)=%x, (unsigned short)htons(type=%x\n", type, htons(type), (unsigned short)htons(type));

    printf("length=%d, hotns(length)=%d, (unsigned short)htons(length)=%d\n", length, htons(length), (unsigned short)htons(length));

    printf("len=%d, ntohs(len)=%d\n", len, ntohs(len));
    return 0;
}
