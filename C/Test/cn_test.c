#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    if(argc != 2)
    {
        printf("Usage: %s 汉字\n", argv[0]);
        return 0;
    }
    printf("中文字节数：\n");
    printf("GB2312:  2 BYTES\n");
    printf("Unicode: 2 BYTES\n");
    printf("UTF-8:   3 BYTES\n");
    printf("srelen(%s)=%d\n", argv[1], strlen(argv[1]));
    return 0;
}


