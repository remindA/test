#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    if(argc != 2)
    {
        printf("Usage :%s bytes\n", argv[0]);
        exit(1);
    }
    long int bytes = atol(argv[1]);
    char *p = (char *)malloc(bytes);
    if(p == NULL)
    {
        printf("Cann't malloc %ld bytes\n", bytes);
        exit(1);
    }
    free(p);
    p = NULL;
    return 0;
}
