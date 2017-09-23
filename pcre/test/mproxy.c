#include <arpa/inet.h>
#include <errno.h>
#include <libgen.h>
#include <netdb.h>
#include <resolv.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/wait.h>
#include <netinet/in.h> 


#include <string.h>

#define BUF_SIZE 8192

#define READ  0
#define WRITE 1

#define DEFAULT_LOCAL_PORT    8080  
#define SERVER_SOCKET_ERROR -1
#define SERVER_SETSOCKOPT_ERROR -2
#define SERVER_BIND_ERROR -3
#define SERVER_LISTEN_ERROR -4
#define CLIENT_SOCKET_ERROR -5
#define CLIENT_RESOLVE_ERROR -6
#define CLIENT_CONNECT_ERROR -7
#define CREATE_PIPE_ERROR -8
#define BROKEN_PIPE_ERROR -9
#define HEADER_BUFFER_FULL -10
#define BAD_HTTP_PROTOCOL -11

char remote_host[128]; 
int remote_port; 
int local_port;
int server_sock; 
int client_sock;
int remote_sock;
char * header_buffer ;

void server_loop();
void stop_server();
void handle_client(int client_sock, struct sockaddr_in client_addr);
void forward_header(int destination_sock);
void forward_data(int source_sock, int destination_sock);
void rewrite_header();
int send_data(int socket,char * buffer,int len );
int receive_data(int socket, char * buffer, int len);
void hand_mproxy_info_req(int sock,char * header_buffer) ;
void get_info(char * output);
const char * get_work_mode() ;
int create_connection() ;
int _main(int argc, char *argv[]) ;



//返回mproxy的运行基本信息
void hand_mproxy_info_req(int sock, char * header) {
    char server_path[255] ;
    char response[8192];
    extract_server_path(header,server_path);
    
    char info_buf[1024];
    get_info(info_buf);
    sprintf(response,"HTTP/1.0 200 OK\nServer: MProxy/0.1\n\
                    Content-type: text/html; charset=utf-8\n\n\
                     <html><body>\
                     <pre>%s</pre>\
                     </body></html>\n",info_buf);


    write(sock,response,strlen(response));

}


/* 处理客户端的连接 */
void handle_client(int client_sock, struct sockaddr_in client_addr)
{

    if ((remote_sock = create_connection()) < 0) {
        return;
    }

    if (fork() == 0) 
    {
        //转发req_header
        //过滤转发body(阻塞)
        exit(0);
    }

    if (fork() == 0) 
    {   
        //接受来自服务器的rsp_header
        //remap转发rsp_header
        //过滤转发数据
        exit(0);
    }

    close(remote_sock);
    close(client_sock);
}


int send_data(int socket,char * buffer,int len)
{
    return send(socket,buffer,len,0);
}

int receive_data(int socket, char * buffer, int len)
{
    int n = recv(socket, buffer, len, 0);
    return n;
}



/* 代理中的完整URL转发前需改成 path 的形式 */
void rewrite_header()
{
    char * p = strstr(header_buffer,"http://");
    char * p0 = strchr(p,'\0');
    char * p5 = strstr(header_buffer,"HTTP/"); /* "HTTP/" 是协议标识 如 "HTTP/1.1" */
    int len = strlen(header_buffer);
    if(p)
    {
        char * p1 = strchr(p + 7,'/');
        if(p1 && (p5 > p1)) 
        {
            //转换url到 path
            memcpy(p,p1,(int)(p0 -p1));
            int l = len - (p1 - p) ;
            header_buffer[l] = '\0';


        } else 
        {
            char * p2 = strchr(p,' ');  //GET http://3g.sina.com.cn HTTP/1.1

            // printf("%s\n",p2);
            memcpy(p + 1,p2,(int)(p0-p2));
            *p = '/';  //url 没有路径使用根
            int l  = len - (p2  - p ) + 1;
            header_buffer[l] = '\0';

        }
    }
}


void forward_data(int source_sock, int destination_sock) {
    char buffer[BUF_SIZE];
    int n;
    while ((n = receive_data(source_sock, buffer, BUF_SIZE)) > 0) 
    { 
        send_data(destination_sock, buffer, n); 
    }
    shutdown(destination_sock, SHUT_RDWR); 
    shutdown(source_sock, SHUT_RDWR); 
}

int create_connection() {
    struct sockaddr_in server_addr;
    struct hostent *server;
    int sock;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        return CLIENT_SOCKET_ERROR;
    }

    if ((server = gethostbyname(remote_host)) == NULL) {
        errno = EFAULT;
        return CLIENT_RESOLVE_ERROR;
    }
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    server_addr.sin_port = htons(remote_port);

    if (connect(sock, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        return CLIENT_CONNECT_ERROR;
    }

    return sock;
}


int create_server_socket(int port) {
    int server_sock, optval;
    struct sockaddr_in server_addr;

    if ((server_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        return SERVER_SOCKET_ERROR;
    }

    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        return SERVER_SETSOCKOPT_ERROR;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
        return SERVER_BIND_ERROR;
    }

    if (listen(server_sock, 20) < 0) {
        return SERVER_LISTEN_ERROR;
    }

    return server_sock;
}

/* 处理僵尸进程 */
void sigchld_handler(int signal) {
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

void server_loop() 
{
    struct sockaddr_in client_addr;
    socklen_t addrlen = sizeof(client_addr);

    while (1) {
        client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &addrlen);
        
        if (fork() == 0) {
            close(server_sock);
            handle_client(client_sock, client_addr);
            exit(0);
        }
        close(client_sock);  //父进程不使用client_fd,所以要关闭一下
    }

}


void start_server(int daemon)
{
    //初始化全局变量
    header_buffer = (char *) malloc(MAX_HEADER_SIZE);

    signal(SIGCHLD, sigchld_handler); // 防止子进程变成僵尸进程

    if ((server_sock = create_server_socket(local_port)) < 0) 
    {
        exit(server_sock);
    }
    server_loop();
}

int main(int argc, char *argv[])
{
    return _main(argc,argv);
}

int _main(int argc, char *argv[]) 
{
    local_port = DEFAULT_LOCAL_PORT;
    io_flag = FLG_NONE;
    int daemon = 0; 
    start_server(daemon);
    return 0;

}
