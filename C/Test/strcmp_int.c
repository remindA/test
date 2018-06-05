#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char **argv)
{
    char str1[] = "abc";
    char str2[] = "abc";
    int *a = (int *)str1;
    int *b = (int *)str2;
    printf("sizeof(str1) == %d\n", sizeof(str1));

    if(*a == *b) {
        printf("%s == %s\n", str1, str2);
    }
    return 0;
}
