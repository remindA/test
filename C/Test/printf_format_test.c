#include <stdio.h>


int main()
{
    char *str = "123456789";
    int i = 0;
    for(i = 0; i < 9; i++)
    {
        printf("%d: %s\n", i+1, str);
        printf("%d: %.*s\n", i+1, i+1, str);
    }

    return 0;
}
