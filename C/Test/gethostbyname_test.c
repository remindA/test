#include <netdb.h>
#include <errno.h>
#include <sys/socket.h>
#include <stdio.h>
#include <arpa/inet.h>

int main(int argc, char **argv)
{
/*    if(argc != 2)
    {
        printf("Usage: %s hostname\n", argv[0]);
        return 0;
    }
*/
    struct hostent *host;
    //if((host = gethostbyname(argv[1])) == NULL)
    if((host = gethostbyname("192.168.1.1")) == NULL)
    {
        perror("gethostbyname");
        return 0;
    }
    char str[32] = {0};
    printf("%s <--> %s\n", "192.168.1.1", inet_ntop(AF_INET, host->h_addr, str, sizeof(str)));
    return 0;
}

