/*
 * =====================================================================================
 *
 *       Filename:  sys_v_shm.c
 *
 *    Description:  测试sys V共享内存
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
#include <sys/sem.h>
#include <sys/shm.h>
#include "semun.h"

typedef struct {
    int sem_prd;
    int sem_con;
    //SSL   *ssl;
    void *ssl;
    unsigned char *shm;
}arg_t;

/* father send to ptr_c, wait for shm_s */
/* child  send to ptr_s, wait for shm_c */
#define SEM_H     0
#define SEM_C_PRD 1
#define SEM_C_CON 2
#define SEM_S_PRD 3
#define SEM_S_CON 4
#define SEM_NUM   5
#define MY_SEM_BLOCK 0
int semid;

#define LEN_SHM ((4096<<8) - sizeof(int))
int shmid_h;
int shmid_c;
int shmid_s;
unsigned char *shm_h;
unsigned char *shm_c;
unsigned char *shm_s;


void do_forward(void *ARG);
int handle_server();
int shm_sem_init();
int my_semop(int semid, unsigned short sem_num, short op, short flag);
int my_semwait(int semid, unsigned short sem_num);
int my_sempost(int semid, unsigned short sem_num);
//uint32_t get_shm_data_len(unsigned char *shm, uint32_t len_shm);
//void write_to_shm(unsigned char *shm, uint32_t len_shm, unsigned char *buff, uint32_t len_buff);
//int  copy_from_shm(unsigned char *buff, uint32_t *len, unsigned char *shm, uint32_t len_shm);
//void clear_shm(unsigned char *shm, uint32_t len_shm);


void sig_handle(int signo)
{
    if(signo == SIGINT) {
        sem_delete();
        shm_delete();
        printf("capture SIGINT\n"); 
        exit(0);
    }
}

int sem_delete()
{
    semctl(semid, 0, IPC_RMID);
    printf("semctl-rmid ok\n");
}

int shm_delete()
{
    shmdt(shm_h);
    shmdt(shm_c);
    shmdt(shm_s);
    shmctl(shmid_h, IPC_RMID, NULL); 
    shmctl(shmid_c, IPC_RMID, NULL);
    shmctl(shmid_s, IPC_RMID, NULL);
    return 0; 
}

/* 创建和初始化如果失败，一定记得删除已经创建的，否则会一直维持在内核中 */
int shm_sem_init()
{
    int ret;
    /* 1. 信号量的创建和初始化 */
    int nsems;
    char  sem_name[100] = {0};
    nsems = SEM_NUM;
    srandom(time(NULL));
    long int r = random();
    sprintf(sem_name, "sysvsem%ld", r);
    semid = semget(IPC_PRIVATE, nsems, IPC_CREAT | IPC_EXCL | 0666);
    if(semid < 0) {
        perror("semget()");
        if(errno == EEXIST) {
            strcat(sem_name, "v2");
            semid = semget(IPC_PRIVATE, nsems, IPC_CREAT | IPC_EXCL | 0666);
            if(semid < 0) {
                perror("semget()");
                return -1;
            }
        }
        else {
            return -1;
        }
    }
    printf("semget() ok, semid = %d\n", semid);

    /* 2. 设置信号集中的所有信号量的初始值 */
    int i;
    union semun arg;
    /* 获取信号集，及其大小，设置信号集的初始化大小 */
    struct semid_ds ds;
    arg.buf = &ds;
    ret = semctl(semid, 0, IPC_STAT, arg);
    printf("ds.sem_nsems = %ld\n", ds.sem_nsems);
    printf("arg.buf->sem_nsems = %ld\n", arg.buf->sem_nsems);
    arg.arry = (unsigned short *)calloc(arg.buf->sem_nsems, sizeof(unsigned short));
    /*
    if(arg.buf->sem_nsems != SEM_NUM) {
        printf("arg.buf->sem_nsems = %ld != %d\n", arg.buf->sem_nsems, SEM_NUM);
        return -1;
    }
    */
    
    arg.arry[SEM_H] = 1;
    arg.arry[SEM_C_PRD] = 1;
    arg.arry[SEM_C_CON] = 0;
    arg.arry[SEM_S_PRD] = 1;
    arg.arry[SEM_S_CON] = 0;
    ret = semctl(semid, 0, SETALL, arg);

    /* 共享内存 */
    size_t len_h, len_c, len_s;
    len_h = len_c = len_s = LEN_SHM + sizeof(int);
    char  shm_name_h[100] = {0};
    char  shm_name_c[100] = {0};
    char  shm_name_s[100] = {0};

    sprintf(shm_name_h, "sysvshmh%ld", r);
    sprintf(shm_name_c, "sysvshmc%ld", r);
    sprintf(shm_name_s, "sysvshms%ld", r);
    shmid_h = shmget(IPC_PRIVATE, len_h, IPC_CREAT | IPC_EXCL | 0666);
    if(shmid_h < 0) {
        perror("shmget() h");
        if(errno == EEXIST) {
            sprintf(shm_name_h, "shm%s", shm_name_h);
            shmid_h = shmget(IPC_PRIVATE, len_h, IPC_CREAT | IPC_EXCL | 0666);
            if(shmid_h < 0) {
                perror("shmget() ");
                return -1;
            }
        }
        else {
            return -1;
        }
    }
    printf("shm_h ok\n");

    shmid_c = shmget(IPC_PRIVATE, len_c, IPC_CREAT | IPC_EXCL | 0666);
    if(shmid_c < 0) {
        perror("shmget() c");
        if(errno == EEXIST) {
            sprintf(shm_name_c, "shm%s", shm_name_c);
            shmid_c = shmget(IPC_PRIVATE, len_c, IPC_CREAT | IPC_EXCL | 0666);
            if(shmid_c < 0) {
                perror("shmget() c");
                return -1;
            }
        }
        else {
            return -1;
        }
    }
    printf("shm_c ok\n");

    shmid_s = shmget(IPC_PRIVATE, len_s, IPC_CREAT | IPC_EXCL | 0666);
    if(shmid_s < 0) {
        perror("shmget() s");
        if(errno == EEXIST) {
            sprintf(shm_name_s, "shm%s", shm_name_s);
            shmid_s = shmget(IPC_PRIVATE, len_s, IPC_CREAT | IPC_EXCL | 0666);
            if(shmid_s < 0) {
                perror("shmget() s");
                return -1;
            }
        }
        else {
            return -1;
        }
    }
    printf("shm_s ok\n");

    shm_h = shmat(shmid_h, NULL, 0);
    if(shm_h == (void *)(-1)) {
        perror("shmat h");
        
        return -1;
    }
    printf("shmat h ok\n");

    shm_c = shmat(shmid_c, NULL, 0);
    if(shm_c == (void *)(-1)) {
        perror("shmat c");
        return -1;
    }
    printf("shmat c ok\n");

    shm_s = shmat(shmid_s, NULL, 0);
    if(shm_s == (void *)(-1)) {
        perror("shmat s");
        return -1;
    }
    printf("shmat s ok\n");

    return 0;
}

/*
 * 使用二进制信号量
 * my_sempost(): 信号量值加1
 * my_semwait(): 等待信号量值变为1,然后值减1
 */
int my_semop(int semid, unsigned short sem_num, short op, short flag)
{
    int semval = semctl(semid, sem_num, GETVAL);
    switch(sem_num) {
        case 0:
            printf(" .SEM_H %d semval == %d, op = %d\n", sem_num, semval, op);
            break;
        case 1:
            printf(" .SEM_C_PRD %d semval == %d, op = %d\n", sem_num, semval, op);
            break;
        case 2:
            printf(" .SEM_C_CON %d semval == %d, op = %d\n", sem_num, semval, op);
            break;
        case 3:
            printf(" .SEM_S_PRD %d semval == %d, op = %d\n", sem_num, semval, op);
            break;
        case 4:
            printf(" .SEM_S_CON %d semval == %d, op = %d\n", sem_num, semval, op);
            break;
        default: 
            break;
    }
    struct sembuf sops[1];
    sops[0].sem_num = sem_num;
    sops[0].sem_op = op;
    sops[0].sem_flg = flag;
    semop(semid, sops, 1);
    semval = semctl(semid, sem_num, GETVAL);
    switch(sem_num) {
        case 0:
            printf("..SEM_H %d semval == %d\n", sem_num, semval);
            break;
        case 1:
            printf("..SEM_C_PRD %d semval == %d\n", sem_num, semval);
            break;
        case 2:
            printf("..SEM_C_CON %d semval == %d\n", sem_num, semval);
            break;
        case 3:
            printf("..SEM_S_PRD %d semval == %d\n", sem_num, semval);
            break;
        case 4:
            printf("..SEM_S_CON %d semval == %d\n", sem_num, semval);
            break;
        default: 
            break;
    }
    return 0;
}


/* wait: wait value become 0, do suff, make value 1 */
int my_semwait(int semid, unsigned short sem_num)
{
    return my_semop(semid, sem_num, -1, MY_SEM_BLOCK);
}

/* post: make value become 0 */
int my_sempost(int semid, unsigned short sem_num)
{
    return my_semop(semid, sem_num, 1, MY_SEM_BLOCK);
}

int main(int argc, char **argv)
{
    signal(SIGINT, sig_handle);
    if(shm_sem_init() < 0) {
        return 0;
    }

    switch(fork()) {
        case 0:
            /* free unrelevant sources */
            handle_server();
            exit(0);
        case -1:
        default:
            break;
    }

    /* This is parent */
    /* free unrelevant sources */
    arg_t arg = {SEM_C_PRD, SEM_C_CON, NULL, shm_c};
    pthread_t th;
    if(pthread_create(&th, NULL, (void *)do_forward, (void *)&arg) != 0) {
        perror("father, pthread_create()");
        return 0;
    }

    srandom(time(NULL));
    long int r;
    int cnt = 0;
    while(1) {
        sleep(1);
        r = random();
        my_semwait(semid, SEM_C_PRD);
        cnt++;
        sprintf((char *)shm_c, "main : %ld", r);
        printf("main send %d\n", cnt);
        my_sempost(semid, SEM_C_CON);
    }

    return 0;
}


/* shm_wait and forward */
void do_forward(void *ARG)
{
    printf("a new thread\n");
    int retval;
    pthread_detach(pthread_self());
    arg_t *arg = (arg_t *)ARG;
    int get = 0;
    while(1) {
        my_semwait(semid, arg->sem_con);
        get++;
        printf("[%s], tot get %d\n\n", (char *)(arg->shm), get);
        my_sempost(semid, arg->sem_prd);
    }
    /* free sources */
    pthread_exit(&retval);
}

int handle_server()
{
    printf("i am child\n");
    arg_t arg = {SEM_S_PRD, SEM_S_CON, NULL, shm_s};
    pthread_t th;
    if(pthread_create(&th, NULL, (void *)do_forward, (void *)&arg) < 0) {
        perror("child, pthread_create()");
    }

    sleep(5);
    srandom(time(NULL));
    long int r;
    char str[1024];
    int cnt = 0;
    while(1) {
        sleep(1);
        r = random();
        my_semwait(semid, SEM_S_PRD);
        cnt++;
        sprintf((char *)shm_s, "handle server: %ld", r);
        printf("handle server send %d\n", cnt);
        my_sempost(semid, SEM_S_CON);
    }

    return 0;
}

/*
   uint32_t get_shm_data_len(unsigned char *shm, uint32_t len_shm)
   {
   uint32_t len = 0;
   memcpy(&len, shm, sizeof(uint32_t));
   if(len > len_shm - sizeof(uint32_t)) {
   printf("get_shm_data_len: length > len_shm - %d\n", len, len_shm, sizeof(uint32_t));
   return 0;
   }
   else if(len == 0) {
   printf("get_shm_data_len: len == 0, no data\n");
   }
   return len;
   }

   void write_to_shm(unsigned char *shm, uint32_t len_shm, unsigned char *buff, uint32_t len_buff)
   {
   if(len_buff > len_shm - sizeof(uint32_t)) {
   printf("write_to_shm: len_buff > len_shm - sizeof(uint32_t), %d > %d - %d\n", len_buff, len_shm, sizeof(uint32_t));
   return;
   }
   memcpy(shm, &len_buff, sizeof(uint32_t));
   memcpy(shm + sizeof(uint32_t), buff, len_buff);
   }

   int  copy_from_shm(unsigned char *buff, uint32_t *len, unsigned char *shm, uint32_t len_shm)
   {
   memcpy(len, shm, sizeof(uint32_t));
   if(*len > len_shm - sizeof(uint32_t)) {
   printf("cpoy_from_shm : length is longer than len_shm. %d > %d\n", *len, len_shm);
   return -1;
   }
   memcpy(buff, shm + sizeof(uint32_t), *len);
   return 0;
   }

   void clear_shm(unsigned char *shm, uint32_t len_shm)
   {
   memset(shm, 0, len_shm);
   }
   */

