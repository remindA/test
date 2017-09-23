#include <stdio.h>

#define JOIN(a,b)  (a##b)
#define STR(a)     (#a)

int main()
{
    char *ab = "hello";
    int   c = 1000;
    printf("%s\n", JOIN("a","b"));
    printf("%s\n", STR(c));
    return 0;
}
