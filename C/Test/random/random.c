#include <time.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>


int get_random()
{
    static unsigned int seed = 0x19950827;
    srandom(seed);
    seed = random();
    return seed;
}

int main(int argc, char **argv)
{
    int i = 1000;
    while(i--) {
        printf("%ld\n", get_random());
    }
    return 0;
}

