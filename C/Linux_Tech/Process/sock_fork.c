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
    int lfd = socket(AF_INET, SOCK_STREAM,  0);
    int cfd = -1;
    if(lfd < 0)
        err_quit("socket");
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    memset(&client_addr, 0, sizeof(client_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8888);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    //inet_pton(AF_INET, "192.168.1.102", &server_addr.sin_addr.sin_addr);
    if(bind(lfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        err_quit("bind");

    if(listen(lfd, 100) < 0)
        err_quit("listen");
    socklen_t s_len = sizeof(client_addr);
    pid_t pid;
#define LEN_IP  16
    char c_ip[LEN_IP] = {0};
    while(1){
        cfd = accept(lfd, (struct sockaddr *)&client_addr, &s_len);
        printf("client online :%s, %d\n", 
                inet_ntop(AF_INET, &client_addr.sin_addr.s_addr, c_ip, sizeof(c_ip)), 
                ntohs(client_addr.sin_port));
        pid = fork();
        if(pid < 0)
            err_quit("fork");
        else if(pid == 0){
            close(lfd);
            break;
        }
        else{
            close(cfd);
            continue;
        }
    }

    if(pid == 0){
        while(1){
            char buff[1024];
            int n = read(cfd, buff, sizeof(buff));
            if(n < 0){
                if(errno == EINTR)
                    continue;
                else{
                    perror("read");
                    exit(0);
                }
            }else if( n == 0){
                close(cfd);
                exit(0);
            }
            else{
                int i = 0;
                for(i = 0; i < n; i++)
                    buff[i] = toupper(buff[i]);
                write(cfd, buff, n);
            }
        }
    }

    return 0;
}

