#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>
#include <poll.h>

#define MAX_FD 5000

void err_quit(const char *api)
{
    perror(api);
    exit(1);
}

int main()
{
    int i, j, n;
    struct pollfd vector[MAX_FD];
    nfds_t nfds;
    char buff[8196] = {0};
    int l_fd = socket(AF_INET, SOCK_STREAM,  0);
    int c_fd = -1;
    if(l_fd < 0)
        err_quit("socket");
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    memset(&client_addr, 0, sizeof(client_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8888);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    //inet_pton(AF_INET, "192.168.1.102", &server_addr.sin_addr.sin_addr);
    if(bind(l_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        err_quit("bind");

    if(listen(l_fd, 100) < 0)
        err_quit("listen");
    socklen_t s_len = sizeof(client_addr);
#define LEN_IP  16
    char c_ip[LEN_IP] = {0};
    for(i = 1; i < MAX_FD; i++)
        vector[i].fd = -1;
    vector[0].fd = l_fd;
    vector[0].events = POLLIN;
    nfds = 1;
    while(1)
    {
        int ret = poll(vector, nfds, -1);
        if(ret < 0)
        {
            perror("select");
            continue;
        }
        if(vector[0].revents & POLLIN)
        {
            c_fd = accept(l_fd, (struct sockaddr *)&client_addr, &s_len);
            if(c_fd < 0)
            {
                perror("accept");
                continue;
            }
            printf("client online :%s, %d\n", 
                    inet_ntop(AF_INET, &client_addr.sin_addr.s_addr, c_ip, sizeof(c_ip)), 
                    ntohs(client_addr.sin_port));
            for(i = 1; i < MAX_FD; i++)
            {
                if(vector[i].fd < 0)
                {
                    vector[i].fd = c_fd;
                    vector[i].events  = POLLIN;
                    vector[i].revents = 0;
                    nfds = nfds > (i + 1)?nfds:(i + 1);
                    break;
                }
            }
            if(i >= MAX_FD)
                printf("too much clients\n");
            if(--ret == 0)          /* rset only l_fd is readable */
                continue;
        }

        for(i = 1; i < nfds; i++)
        {
            if(vector[i].revents & POLLIN)
            {
                printf("%d isreadable\n", vector[i].fd);
                n = read(vector[i].fd, buff, sizeof(buff));
                printf("n = %d\n", n);
                if(n == 0)
                {
                    close(vector[i].fd);
                    vector[i].fd = -1;
                    printf("client offline\n");
                }
                else if(n < 0)
                {
                    if(errno == ECONNRESET)
                    {
                        printf("connection reset\n");
                        close(vector[i].fd);
                        vector[i].fd = -1;
                    }
                    perror("read");
                }
                else
                {
                    for(j = 0; j < n; j++)
                        buff[j] = toupper(buff[j]);
                    write(vector[i].fd, buff, n);
                }
            }
        }

    }

    return 0;
}

