/*
 * =====================================================================================
 *
 *       Filename:  posix_shared_memory.c
 *
 *    Description:  测试posix共享内存的使用
 *
 *        Version:  1.0
 *        Created:  2018年01月05日 14时10分12秒
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

#include <sys/mman.h>
#include <pthread.h>
#include <semaphore.h>
#define LEN_SHM 1000

typedef struct {
    sem_t *sem_prd;
    sem_t *sem_con;
    //SSL   *ssl;
    void *ssl;
    unsigned char *shm;
    int  fd;
}arg_t;

/* father send to ptr_c, wait for shm_s */
/* child  send to ptr_s, wait for shm_c */
int fd_c, fd_s;
unsigned char *ptr_c, *ptr_s;
sem_t *sem_c_con, *sem_c_prd;
sem_t *sem_s_con, *sem_s_prd;

void do_forward(void *ARG);
int handle_server();
uint32_t get_shm_data_len(unsigned char *shm, uint32_t len_shm);
void write_to_shm(unsigned char *shm, uint32_t len_shm, unsigned char *buff, uint32_t len_buff);
int  copy_from_shm(unsigned char *buff, uint32_t *len, unsigned char *shm, uint32_t len_shm);
void clear_shm(unsigned char *shm, uint32_t len_shm);


void sig_handle(int signo)
{
    if(signo == SIGINT) {
        //释放shm, sem
        if(munmap(ptr_c, LEN_SHM) < 0) {
            perror("munmap shm_c");
        }
        if(munmap(ptr_s, LEN_SHM) < 0) {
            perror("munmap shm_s");
        }
        printf("capture SIGINT\n");
        exit(0);
    }
}


int main(int argc, char **argv)
{
    signal(SIGINT, sig_handle);
    int flags_c, flags_s;
    off_t len_c, len_s;
    //srandom(time(NULL));
    //long int r = random();
    flags_c = flags_s = O_RDWR | O_CREAT | O_EXCL;
    if(argc != 3) {
        printf("usage: %s name len\n", argv[0]);
        return 0;
    }

    char name_c[100] = {0};
    char name_s[100] = {0};
    sprintf(name_c, "%sc", argv[1]);
    sprintf(name_s, "%ss", argv[1]);
    //len_c = len_s = atoi(argv[2]);
    len_c = len_s = LEN_SHM;
    fd_c = shm_open(name_c, flags_c, 0666);
    fd_s = shm_open(name_s, flags_s, 0666);
    if(fd_c < 0) {
        perror("c : shm_open()");
        if(errno != EEXIST) {
            return 0;
        }
        fd_c = shm_open(name_c, O_RDWR, 0600);
        if(fd_c < 0) {
            perror("c : shm_open() a exist");
            return 0;
        }
    }
    if(fd_s < 0) {
        perror("s : shm_open()");
        if(errno != EEXIST) {
            return 0;
        }
        fd_s = shm_open(name_s, O_RDWR, 0600);
        if(fd_s < 0) {
            perror("s : shm_open() a exist");
            return 0;
        }
    }

    /* 调整共享内存区的大小 */
    ftruncate(fd_c, len_c);
    ptr_c = mmap(NULL, len_c, PROT_WRITE | PROT_READ, MAP_SHARED, fd_c, 0);
    if(MAP_FAILED == ptr_c) {
        perror("c : mmap()");
        return 0;
    }
    ftruncate(fd_s, len_s);
    ptr_s = mmap(NULL, len_s, PROT_WRITE | PROT_READ, MAP_SHARED, fd_s, 0);
    if(MAP_FAILED == ptr_s) {
        perror("s : mmap()");
        return 0;
    }

    shm_unlink(name_c);
    shm_unlink(name_s);

    char  *sem_name_c_con = "mysemccon";
    char  *sem_name_c_prd = "mysemcprd";
    char  *sem_name_s_con = "mysemscon";
    char  *sem_name_s_prd = "mysemsprd";
     
    sem_c_con = sem_open(sem_name_c_con, O_CREAT | O_EXCL, 0666, 1);
    sem_c_prd = sem_open(sem_name_c_prd, O_CREAT | O_EXCL, 0666, 1);
    sem_s_con = sem_open(sem_name_s_con, O_CREAT | O_EXCL, 0666, 1);
    sem_s_prd = sem_open(sem_name_s_prd, O_CREAT | O_EXCL, 0666, 1);
    if(SEM_FAILED == sem_c_con) {
        perror("cannot open a sem_c_con, sem_open()");
        if(errno != EEXIST) {
            return 0;
        }
        sem_c_con = sem_open(sem_name_c_con, 0);
        if(SEM_FAILED == sem_c_con) {
            perror("cannot open a exist sem_c_con, sem_open()");
            return 0;
        }
    }
    
    printf("open sem_c_con\n");
    if(SEM_FAILED == sem_s_con) {
        perror("cannot open a sem_s_con, sem_open()");
        if(errno != EEXIST) {
            return 0;
        }
        sem_s_con = sem_open(sem_name_s_con, 0);
        if(SEM_FAILED == sem_s_con) {
            perror("cannot open a exist sem_s_con, sem_open()");
            return 0;
        }
    }
    printf("open sem_s_con\n");
    if(SEM_FAILED == sem_c_prd) {
        perror("cannot open a sem_c_prd, sem_open()");
        if(errno != EEXIST) {
            return 0;
        }
        sem_c_prd = sem_open(sem_name_c_prd, 0);
        if(SEM_FAILED == sem_c_prd) {
            perror("cannot open a exist sem_c_prd, sem_open()");
            return 0;
        }
    }
    
    printf("open sem_c_prd\n");
    if(SEM_FAILED == sem_s_prd) {
        perror("cannot open a sem_s_prd, sem_open()");
        if(errno != EEXIST) {
            return 0;
        }
        sem_s_prd = sem_open(sem_name_s_prd, 0);
        if(SEM_FAILED == sem_s_prd) {
            perror("cannot open a exist sem_s_prd, sem_open()");
            return 0;
        }
    }
    printf("open sem_s_prd\n");
    sem_unlink(sem_name_c_con);
    sem_unlink(sem_name_s_con);
    sem_unlink(sem_name_c_prd);
    sem_unlink(sem_name_s_prd);
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
    arg_t arg = {sem_c_prd, sem_c_con, NULL, ptr_c, fd_c};
    pthread_t th;
    if(pthread_create(&th, NULL, (void *)do_forward, (void *)&arg) != 0) {
        perror("father, pthread_create()");
        return 0;
    }

    srandom(time(NULL));
    long int r;
    char str[1024];
    int cnt = 0;
    sem_post(sem_c_prd);
    while(1) {
        //read process wirte to shm_c
        sem_wait(sem_c_prd);
        cnt++;
        //usleep(10000);  /* 模仿read阻塞１秒钟 */
        sleep(1);
        r = random();
        sprintf(str, "client : %ld\n", r);
        //printf("<%d> client : %ld\n", cnt, r);
        write_to_shm(ptr_c, LEN_SHM, str, strlen(str));
        if(sem_post(sem_c_con) < 0) {
            perror("father sem_post()");
        }
        //printf("client tot_send = %d\n", cnt);
        //printf("father sem_post client\n");
    }

    //进程退出后不会删除共享内存区对象
    //需要使用shmunlink()并ummap()
    return 0;
}


/* shm_wait and forward */
void do_forward(void *ARG)
{
    printf("a new thread\n");
    int retval;
    pthread_detach(pthread_self());
    arg_t *arg = (arg_t *)ARG;
    struct stat st;
    /*　传入参数 ssl, fd */
    int cnt = 0;
    while(1) {
        if(sem_wait(arg->sem_con) < 0) {
            perror("sem_wait()");
            continue;
        }
        fstat(arg->fd, &st);
        cnt++;
        uint32_t len_buff;
        unsigned char buff[LEN_SHM] = {0};
        copy_from_shm(buff, &len_buff, arg->shm, LEN_SHM); 
        buff[len_buff - 1] = '\0';
        //printf("<%d> %s\n\n", cnt, (char *)buff);
        memset(arg->shm, 0, st.st_size);
        //printf("thread_%d total get cnt = %d\n", getpid(), cnt);
        sem_post(arg->sem_prd);
    }
    /* free sources */
    pthread_exit(&retval);
}

int handle_server()
{
    printf("i am child\n");
    arg_t arg = {sem_s_prd, sem_s_con, NULL, ptr_s, fd_s};
    pthread_t th;
    if(pthread_create(&th, NULL, (void *)do_forward, (void *)&arg) < 0) {
        perror("child, pthread_create()");
    }

    sleep(1);
    srandom(time(NULL));
    long int r;
    char str[1024];
    int cnt = 0;
    sem_post(sem_s_prd);
    while(1) {
        //read from server, process, write to shm_s
        sem_wait(sem_s_prd);
        cnt++;
        //usleep(10000);   /* 模仿read阻塞读 */
        sleep(1);
        r = random();
        sprintf(str, "server: %ld", r);
        //printf("<%d> server: %ld\n", cnt, r);
        write_to_shm(ptr_s, LEN_SHM, str, strlen(str));
        if(sem_post(sem_s_con) < 0) {
            perror("child sem_post()");
        }
        //printf("server tot send = %d\n", cnt);
        //printf("child sem_post server\n");
    }

}

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
