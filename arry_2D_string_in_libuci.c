#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

enum{
    OK=0,
    BAD,
    GOOD
};

static char *msg[]={
    [OK]    = "OK",
    [BAD]   = "BAD",
    [GOOD]  = "GOOD"
};


int main(int argc, char **argv)
{
    printf("%s\n", msg[OK]);
    printf("%s\n", msg[BAD]);
    printf("%s\n", msg[GOOD]);
    return 0;
}


