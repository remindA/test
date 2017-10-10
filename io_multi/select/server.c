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

void err_quit(const char *api)
{
    perror(api);
    exit(1);
}

int main()
{
    int i, j, max_i, n;
    int vector[1024];
    char buff[8196] = {0};
    fd_set rset, allset;
    int max_fd;
    FD_ZERO(&rset);
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
    for(i = 0; i < 1024; i++)
        vector[i] = -1;
    FD_SET(l_fd, &allset);
    max_fd = l_fd + 1;
    max_i  = -1;
    while(1)
    {
        rset = allset;
        int ret = select(max_fd, &rset, NULL, NULL, NULL);
        if(ret < 0)
        {
            perror("select");
            continue;
        }
        if(FD_ISSET(l_fd, &rset) > 0)
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
            for(i = 0; i < 1024; i++)
            {
                if(vector[i] < 0)
                {
                    vector[i] = c_fd;
                    FD_SET(c_fd, &allset);
                    max_fd = max_fd > (c_fd + 1)?max_fd:(c_fd + 1);
                    max_i = max_i > i?max_i:i;
                    break;
                }
            }
            if(i >= 1024)
                printf("too much clients\n");
            if(--ret == 0)          /* rset only l_fd is readable */
                continue;
        }

        for(i = 0; i <= max_i; i++)
        {
            if(FD_ISSET(vector[i], &rset))
            {
                printf("%d isreadable\n", vector[i]);
                n = read(vector[i], buff, sizeof(buff));
                printf("n = %d\n", n);
                if(n == 0)
                {
                    close(vector[i]);
                    FD_CLR(vector[i], &allset);
                    vector[i] = -1;
                    printf("client offline\n");
                }
                else if(n < 0)
                    perror("read");
                else
                {
                    for(j = 0; j < n; j++)
                        buff[j] = toupper(buff[j]);
                    write(vector[i], buff, n);
                }
            }
        }

    }

    return 0;
}

