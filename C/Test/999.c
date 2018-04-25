#include <stdio.h>
#include <string.h>

int main()
{
    int i, j , m , n;
    for(i = 0 ; i < 256; i++)
    {
        for(j = 0; j < 256; j++)
        {
            for(m = 0; m < 256; m++)
            {
                for(n = 0; n < 256; n++)
                    printf("%d.%d.%d.%d\n", i, j, m, n);
            }
        }
    }
    return 0;
}
