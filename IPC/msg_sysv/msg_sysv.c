/*
 * =====================================================================================
 *
 *       Filename:  msg_sysv.c
 *
 *    Description:  测试sys V消息队列
 *
 *        Version:  1.0
 *        Created:  2018年01月11日 21时13分00秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <math.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>

#include <sys/ipc.h>
#include <sys/msg.h>

typedef struct {
    //void *ssl;
    int msgid;
    long msg_type;
}arg_t;

#define LEN_SSL_RECORD  16384

#define MSG_FIRST  0
#define MSG_CLIENT 1
#define MSG_SERVER 2

typedef struct {
    long type;
    unsigned short len;
    unsigned char data[LEN_SSL_RECORD];
}msg_t;


int msgid_c;
int msgid_s;


void do_forward(void *ARG);
int handle_server();
int sysv_msg_init();
static inline int sysv_msg_del(int msgid);

void sig_handle(int signo)
{
    if(signo == SIGINT) {
        sysv_msg_del_all();
        printf("capture SIGINT\n"); 
        exit(0);
    }
}

void sysv_msg_del_all()
{
    sysv_msg_del(msgid_c);
    sysv_msg_del(msgid_s);
}

static inline int sysv_msg_del(int msgid)
{
    int ret = msgctl(msgid, IPC_RMID, NULL);
    if(ret < 0) {
        perror("msgctl, sysv_msg_del");
    }
    return ret;
}

int sysv_msg_init()
{
    int ret;
    msgid_c = msgget(IPC_PRIVATE,  IPC_CREAT | IPC_EXCL | 0666);
    if(msgid_c < 0) {
        perror("msgget id_c");
        return -1;
    }
    printf("msgget msgid_c\n");

    msgid_s = msgget(IPC_PRIVATE,  IPC_CREAT | IPC_EXCL | 0666);
    if(msgid_s < 0) {
        perror("msgget id_s");
        sysv_msg_del(msgid_c); 
        return -1;
    }
    printf("msgget msgid_s\n");

    return 0;
}


int main(int argc, char **argv)
{
    signal(SIGINT, sig_handle);
    if(sysv_msg_init() < 0) {
        return 0;
    }

    switch(fork()) {
        case 0:
            handle_server();
            exit(0);
        case -1:
            sysv_msg_del_all();
            exit(0);
        default:
            break;
    }

    arg_t arg = {msgid_s, MSG_SERVER};
    pthread_t th;
    if(pthread_create(&th, NULL, (void *)do_forward, (void *)&arg) != 0) {
        perror("father, pthread_create()");
        return 0;
    }

    srandom(time(NULL));
    long int r;
    msg_t msg = {MSG_CLIENT};
    while(1) {
        sleep(1);
        r = random();
        sprintf((char *)(msg.data), "client send: %ld", r);
        msg.type = MSG_CLIENT;
        msg.len = strlen((char *)(msg.data));
        if(msgsnd(msgid_c, &msg, sizeof(msg_t) - sizeof(long), 0) < 0) {
            perror("msgsnd()");
        }
    }

    return 0;
}


/* shm_wait and forward */
void do_forward(void *ARG)
{
    printf("===start do_forward(%d)=====\n", getpid());
    int retval;
    pthread_detach(pthread_self());
    arg_t *arg = (arg_t *)ARG;
    msg_t msg;
    while(1) {
        if(msgrcv(arg->msgid, &msg, sizeof(msg_t) - sizeof(long), arg->msg_type, 0) < 0) {
            perror("msgrcv()");
            continue;
        }
        msg.data[msg.len] = '\0';
        printf("do_forward_%d, [%s]\n", getpid(), msg.data);
    }
    /* free sources */
    pthread_exit(&retval);
}

int handle_server()
{
    arg_t arg = {msgid_c, MSG_CLIENT};
    pthread_t th;
    if(pthread_create(&th, NULL, (void *)do_forward, (void *)&arg) < 0) {
        perror("child, pthread_create()");
        return 0;
    }

    sleep(1);
    srandom(time(NULL));
    long int r;
    msg_t msg = {MSG_SERVER}; 
    while(1) {
        sleep(1);
        r = random();
        sprintf((char *)(msg.data), "client send: %ld", r);
        msg.type = MSG_SERVER;
        msg.len = strlen((char *)(msg.data));
        if(msgsnd(msgid_s, &msg, sizeof(msg_t) - sizeof(long), 0) < 0) {
            perror("msgsnd()");
        }
    }
    return 0;
}

