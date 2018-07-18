#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    sleep(100);
    int *t = NULL;
    printf("t = %d\n", *t);
    return 0;
}
