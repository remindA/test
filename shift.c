#include <stdio.h>

void shift(unsigned char high, unsigned char low);

int main(int argc, char **argv)
{
    if(argc != 3)
    {
        printf("Usage: %s [0-9] [0-9]\n", argv[0]);
    }
    shift((unsigned char)atoi(argv[1]), (unsigned char)atoi(argv[2]));
    return 0;
}

void shift(unsigned char high, unsigned char low)
{
    printf("0x%d%d\n", high, low);
    unsigned short value = high<<4 + low;
    printf("value=%d\n", value);
    printf("value=0x%02x\n", value);
    return;
}
