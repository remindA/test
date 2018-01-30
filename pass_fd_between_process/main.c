/*
 * =====================================================================================
 *
 *       Filename:  main.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年01月22日 15时29分37秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */


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
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <arpa/inet.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <linux/prctl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
typedef struct {
    int c2s;
    int s2c;
}msqid_pair_t;

typedef struct {
    int fd;
    msqid_pair_t msqids;
}workmsg_t;

int sockfd[2];


int worker_handle_client();
ssize_t read_fd(int fd, void *ptr, size_t nbytes, int *recvfd);
ssize_t write_fd(int fd, void *ptr, size_t nbytes, int sendfd);


int main(int argc, char **argv)
{

    int c_fd = open("father", O_RDWR | O_CREAT, 0666); 
    if(c_fd < 0){
        perror("open()");
        return 0;
    }
    int ret  = socketpair(AF_LOCAL, SOCK_STREAM, 0, sockfd);
    if(ret < 0) {
        perror("socketpair()");
        return 0;
    }
    
    printf("sockfd[0] = %d, sockfd[1] = %d\n", sockfd[0], sockfd[1]);
    switch(fork()){
        case -1:
            perror("fork()");
            return 0;
        case 0:
            close(sockfd[1]);
            worker_handle_client();
            exit(1);
        default:
            break;
    }
    workmsg_t msg;
    msg.fd = c_fd;
    msg.msqids.c2s = 123;
    msg.msqids.s2c = 321;
    close(sockfd[0]);
    ret = write_fd(sockfd[1], &(msg.msqids), sizeof(msg.msqids), msg.fd);
    if(ret < 0) {
        return 0;
    }
    printf("father write_fd: fd = %d, msqids.c2s = %d, msqids.s2c = %d\n", msg.fd, msg.msqids.c2s, msg.msqids.s2c);
    close(msg.fd);
    while(1) {
        ret = read_fd(sockfd[1], &(msg.msqids), sizeof(msg.msqids), &(msg.fd));
        if(ret < 0) {
            printf("read_fd ret %d < 0\n", ret);
            break;
        }
        if(ret == 0) {
            printf("read_fd : 0\n");
            break;
        }
        if(ret > 0) {
            printf("father rcv msqids.c2s = %d, msqid.s2c = %d, fd = %d\n", msg.msqids.c2s, msg.msqids.s2c, msg.fd);
            write(msg.fd, "father\n", 7);
            close(msg.fd);
            break;
        }
    }

    return 0;
}

int worker_handle_client()
{
    int ret;
    workmsg_t msg;
    printf("this is child\n");
    while(1) {
        ret = read_fd(sockfd[0], &(msg.msqids), sizeof(msg.msqids), &(msg.fd));
        if(ret <= 0) {
            printf("child: ret = %d <= 0\n", ret);
            break;
        }
        if(msg.fd < 0) {
            printf("read fd not good, fd = %d < 0\n", msg.fd);
            break;
        }
        else {
            printf("read fd ok fd = %d, msqids.c2s = %d, msqids.s2c = %d\n", msg.fd, msg.msqids.c2s, msg.msqids.s2c);
            write(msg.fd, "child\n", 6);
            close(msg.fd);
            msg.fd = open("child", O_RDWR | O_CREAT, 0666);
            if(msg.fd < 0) {
                perror("open()");
            }
            msg.msqids.c2s += 1;
            msg.msqids.s2c += 1;
            write_fd(sockfd[0], &(msg.msqids), sizeof(msg.msqids), msg.fd);
            close(msg.fd);
            break;
        }
    }

    return 0;
}


/* read_fd: copy from unix network programming V1 P335 */
ssize_t read_fd(int fd, void *ptr, size_t nbytes, int *recvfd)
{
    struct msghdr msg;
    struct iovec iov[1];
    ssize_t n;
    union {
        struct cmsghdr cm;
        char control[CMSG_SPACE(sizeof(int))];
    }control_un;
    struct cmsghdr *cmptr;

    msg.msg_control = control_un.control;
    msg.msg_controllen = sizeof(control_un.control);
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    iov[0].iov_base = ptr;
    iov[0].iov_len  = nbytes;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    if((n = recvmsg(fd, &msg, 0)) < 0) {
        perror("recvmsg()");
        return n;
    }
    else if(n == 0) {
        printf("recvmsg: eof\n");
        return n;
    }

    if((cmptr = CMSG_FIRSTHDR(&msg)) != NULL &&
            cmptr->cmsg_len == CMSG_LEN(sizeof(int))) {
        if(cmptr->cmsg_level != SOL_SOCKET) {
            //err_quit("control level != SOL_SOCKET");
            perror("control level != SOL_SOCKET");
            *recvfd = -1;
        }
        if(cmptr->cmsg_type != SCM_RIGHTS) {
            //err_quit("control type != SCM_RIGHTS");
            perror("control type != SCM_RIGHTS");
            *recvfd = -1;
        }
        *recvfd = *((int *)CMSG_DATA(cmptr));
    }
    else 
        *recvfd = -1;
    return n;
}

/* write_fd: copy from unix network programming V1 P336 */
ssize_t write_fd(int fd, void *ptr, size_t nbytes, int sendfd)
{
    struct msghdr msg;
    struct iovec iov[1];
    union{
        struct cmsghdr cm;
        char control[CMSG_SPACE(sizeof(int))];
    }control_un;
    struct cmsghdr *cmptr;
    msg.msg_control = control_un.control;
    msg.msg_controllen = sizeof(control_un.control);

    cmptr = CMSG_FIRSTHDR(&msg);
    cmptr->cmsg_len = CMSG_LEN(sizeof(int));
    cmptr->cmsg_level = SOL_SOCKET;
    cmptr->cmsg_type = SCM_RIGHTS;
    *((int *)CMSG_DATA(cmptr)) = sendfd;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    iov[0].iov_base = ptr;
    iov[0].iov_len = nbytes;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    int ret = sendmsg(fd, &msg, 0);
    printf("write_fd : fd = %d, sendfd = %d\n", fd, sendfd);
    if(ret < 0) {
        perror("sendmsg()");
    }
    return ret;
}
