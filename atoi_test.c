#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    char *str1 = "123";
    char *str2 = " 456";
    char *str3 = " 789 ";

    printf("[%s]\t:%d\n", str1, atoi(str1));
    printf("[%s]\t:%d\n", str2, atoi(str2));
    printf("[%s]\t:%d\n", str3, atoi(str3));
    return 0;
}


