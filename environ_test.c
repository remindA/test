#include <stdio.h>
#include <string.h>

extern char **environ;

int main(int argc, char **argv)
{
    char **p = environ;
    for(; *p != NULL; p++)
        printf("%s\n", *p);

    return 0;
}
