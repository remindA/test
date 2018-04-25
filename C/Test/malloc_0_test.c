#include <stdio.h>
#include <stdlib.h>

int main()
{
    char *p = (char *)malloc(0);
    printf("p=%p\n", p);
    return 0;
}
