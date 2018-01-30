#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    char *str1 = "123";
    char *str2 = " 456";
    char *str3 = " 789 ";
    char *str4 = "abc";
    char *str5 = "123\r\n";

    printf("[%s]\t:%d\n", str1, atoi(str1));
    printf("[%s]\t:%d\n", str2, atoi(str2));
    printf("[%s]\t:%d\n", str3, atoi(str3));
    printf("[%s]\t:%d\n", str4, atoi(str4));
    printf("[%s]\t:%d\n", str5, atoi(str5));
    return 0;
}


