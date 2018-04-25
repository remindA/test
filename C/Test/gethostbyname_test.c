#include <netdb.h>
#include <errno.h>
#include <sys/socket.h>
#include <stdio.h>
#include <arpa/inet.h>

int main(int argc, char **argv)
{
    if(argc != 2)
    {
        printf("Usage: %s hostname\n", argv[0]);
        return 0;
    }
    struct hostent *host;
    if((host = gethostbyname(argv[1])) == NULL)
    {
        perror("gethostbyname");
        return 0;
    }
    char str[32] = {0};
    printf("%s <--> %s\n", argv[1], inet_ntop(AF_INET, host->h_addr, str, sizeof(str)));
    return 0;
}

