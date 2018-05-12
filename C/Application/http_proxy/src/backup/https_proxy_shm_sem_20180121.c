/*
 * =====================================================================================
 *
 *       Filename:  https_proxy.c
 *
 *    Description:  https代理
 *
 *        Version:  1.0
 *        Created:  2018年01月04日 13时31分20秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#define PCRE2_CODE_UNIT_WIDTH 8
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
#include <sys/stat.h>
#include <sys/wait.h>
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

#include "err_quit.h"
#include "http.h"
#include "list.h"
#include "pad_rplstr.h"
#include "safe_free.h"
#include "include.h"
#include "str_replace.h"
#include "config.h"

extern int h_errno;    /* #include <netdb.h> */

/* 共享内存和信号量=============头文件 */
#include "semun.h"
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#ifdef OpenWrt
#include <sys/mman.h>
#include <semaphore.h>
#endif



/* 共享内存和信号量=============线程传参 */
typedef struct _thread_arg {
    unsigned char *shm;
    SSL   *ssl;
    int semid;
    int sem_prd;
    int sem_con;
#ifdef OpenWrt
    int   fd;
    sem_t *sem_prd;
    sem_t *sem_con;
#endif
}thread_arg_t;

/* 共享内存和信号量 */
/* 共享内存实际映射的大小是一个页面4k的倍数 */
/* 定义共享内存大小为1MB. */
/* shm_c发送的都是请求消息，不会太大，　需要设置小点 */
/* shm_s发送的都是响应消息，有很大可能性，　需要设置大点 */
#define LEN_SHM ((1024*1024)-sizeof(int))
unsigned char *shm_h;
unsigned char *shm_c;
unsigned char *shm_s;

/* 共享内存和信号量=============创建 */
#define SEM_H     0
#define SEM_C_PRD 1
#define SEM_C_CON 2
#define SEM_S_PRD 3
#define SEM_S_CON 4
#define SEM_NUM   5
#define MY_SEM_BLOCK 0
int semid;
int shmid_h;
int shmid_c;
int shmid_s;
#ifdef OpenWrt
int fd_h;
int fd_c;
int fd_s;
sem_t *sem_h;
sem_t *sem_c_con;
sem_t *sem_c_prd;
sem_t *sem_s_con;
sem_t *sem_s_prd;
#endif

/* openssl */
SSL *ssl_s;
SSL *ssl_c;
SSL_CTX *ctx_s;
SSL_CTX *ctx_c;
char *ca_cert_file = "ca.crt";
char *server_cert_file = "server.crt";
char *private_key_file = "server.key";


/* 其他 */
int l_fd;
int c_fd;
int wake;
pcre2_code *re;
pcre2_code *ge_re;
struct list_head *remap_table;
struct list_head *regex_table;

/* 函数声明 */
typedef void(*sighandler_t)(int);
/* sysv sem and shm */
//#ifdef SR04I
int sysv_sem_delete();
int sysv_shm_delete();
int sysv_shm_sem_init();
int sysv_my_semop(int semid, unsigned short sem_num, short op, short flag);
int sysv_my_semwait(int semid, unsigned short sem_num);
int sysv_my_sempost(int semid, unsigned short sem_num);
//#endif

int shm_sem_init();
void shm_sem_destory();

int ssl_init(void);
int print_ssl_error(SSL *ssl, int ret);
int get_shm_data_len(unsigned char *shm, int len_shm);
int write_to_shm(thread_arg_t *arg, int len_shm, char *fmt, ...);
int handle_client();
void do_forward(void *ARG);
int handle_server();
int read_process_to_shm(thread_arg_t *arg);
int get_all_chunk_m(SSL *ssl, unsigned char **all_chunk, unsigned int *len);
int forward_http_chunked(thread_arg_t *arg, int len_shm, int encd, int direction, pcre2_code *re);
int forward_txt(http_header_t *header, unsigned char *body, int len, int whole, int encd, thread_arg_t *arg, int len_shm, int direction, pcre2_code *re);
int read_forward_none_txt(thread_arg_t *arg, int len_shm, int len_body, const char *comment);
int create_proxy_server(char *host, short l_port, int listen_num);
int create_real_server(const char *host, short port);
int create_real_server_nonblock(const char *host, short port, int sec);
PCRE2_SPTR replace_content_default_m(char *old, int direction, pcre2_code *re);
int rewrite_url(char *url, pcre2_code *re);
int replace_field(char *field_value, int direction, pcre2_code *re);
int replace_http_header(http_header_t *header, pcre2_code *re);
int get_gunzip(unsigned char *src, unsigned int len_s, char **dst, unsigned int *len_d);
void sig_handle(int signo);
void sig_handle_2(int signo);
int proxy_listen(void);


#ifdef OpenWrt
int posix_shm_sem_init()
{
#ifdef FUNC
    printf("==========start shm_sem_init()==========\n");
#endif
    /* 这块代码及其不好维护，后面肯定要使用数据和循环来简化代码 */
    //进程退出的时候销毁信号量和共享内存
    /* 三个共享内存区域，２对信号量，１个独立信号量 */
    int ret;
    off_t len_c, len_s, len_h;
    char sem_name_h[100] = {0};
    char sem_name_c_con[100] = {0};
    char sem_name_c_prd[100] = {0};
    char sem_name_s_con[100] = {0};
    char sem_name_s_prd[100] = {0};

    char shm_name_h[100] = {0};
    char shm_name_c[100] = {0};
    char shm_name_s[100] = {0};
    //sem名称可能不规范
    srandom(time(NULL));
    long int r = random();

    sprintf(sem_name_h, "semh%ld", r);
    sprintf(sem_name_c_con, "semccon%ld", r);
    sprintf(sem_name_c_prd, "semcprd%ld", r);
    sprintf(sem_name_s_con, "semscon%ld", r);
    sprintf(sem_name_s_prd, "semsprd%ld", r);
    //shm名称可能不规范
    sprintf(shm_name_h, "shmh%ld", r);
    sprintf(shm_name_c, "shmc%ld", r);
    sprintf(shm_name_s, "shms%ld", r);


    /* 1. 创建，初始化信号量 */
    sem_h = sem_open(sem_name_h, O_CREAT | O_EXCL, 0666, 0);
    sem_c_con = sem_open(sem_name_c_con, O_CREAT | O_EXCL, 0666, 0);
    sem_c_prd = sem_open(sem_name_c_prd, O_CREAT | O_EXCL, 0666, 1);
    sem_s_con = sem_open(sem_name_s_con, O_CREAT | O_EXCL, 0666, 0);
    sem_s_prd = sem_open(sem_name_s_prd, O_CREAT | O_EXCL, 0666, 1);
    if(SEM_FAILED == sem_h) {
        perror("cannot open sem_h, sem_open()");
        if(errno != EEXIST) {
            return -1;
        }
        sprintf(sem_name_h, "sem%s", sem_name_h);
        sem_h = sem_open(sem_name_h, O_CREAT | O_EXCL, 0666, 0);
        if(SEM_FAILED == sem_h) {
            perror("cannot open sem_h, sem_open()");
            return -1;
        }
    }
    sem_unlink(sem_name_h);
    printf("open sem_h\n");

    if(SEM_FAILED == sem_c_con) {
        perror("cannot open sem_c_con, sem_open()");
        if(errno != EEXIST) {
            return -1;
        }
        sprintf(sem_name_c_con, "sem%s", sem_name_c_con);
        sem_c_con = sem_open(sem_name_c_con, O_CREAT | O_EXCL, 0666, 0);
        if(SEM_FAILED == sem_c_con) {
            perror("cannot open sem_c_con, sem_open()");
            return -1;
        }
    }
    sem_unlink(sem_name_c_con);
    printf("open sem_c_con\n");

    if(SEM_FAILED == sem_c_prd) {
        perror("cannot open sem_c_prd, sem_open()");
        if(errno != EEXIST) {
            return -1;
        }
        sprintf(sem_name_c_prd, "sem%s", sem_name_c_prd);
        sem_c_prd = sem_open(sem_name_c_prd, O_CREAT | O_EXCL, 0666, 1);
        if(SEM_FAILED == sem_c_prd) {
            perror("cannot open sem_c_prd, sem_open()");
            return -1;
        }
    }
    sem_unlink(sem_name_c_prd);
    printf("open sem_c_prd\n");

    if(SEM_FAILED == sem_s_con) {
        perror("cannot open sem_s_con, sem_open()");
        if(errno != EEXIST) {
            return -1;
        }
        sprintf(sem_name_s_con, "sem%s", sem_name_s_con);
        sem_s_con = sem_open(sem_name_s_con, O_CREAT | O_EXCL, 0666, 0);
        if(SEM_FAILED == sem_s_con) {
            perror("cannot open sem_s_con, sem_open()");
            return -1;
        }
    }
    sem_unlink(sem_name_s_con);
    printf("open sem_s_con\n");

    if(SEM_FAILED == sem_s_prd) {
        perror("cannot open sem_s_prd, sem_open()");
        if(errno != EEXIST) {
            return -1;
        }
        sprintf(sem_name_s_prd, "sem%s", sem_name_s_prd);
        sem_s_prd = sem_open(sem_name_s_prd, O_CREAT | O_EXCL, 0666, 1);
        if(SEM_FAILED == sem_s_prd) {
            perror("cannot open sem_s_prd, sem_open()");
            return -1;
        }
    }
    sem_unlink(sem_name_s_prd);
    printf("open sem_s_prd\n");


    /* 2. 创建，初始化共享内存 */
    len_h = len_c = len_s = LEN_SHM + sizeof(int);
    fd_h = shm_open(shm_name_h, O_RDWR | O_CREAT | O_EXCL, 0666);
    fd_c = shm_open(shm_name_c, O_RDWR | O_CREAT | O_EXCL, 0666);
    fd_s = shm_open(shm_name_s, O_RDWR | O_CREAT | O_EXCL, 0666);
    if(fd_h < 0) {
        perror("h : shm_open()");
        if(errno != EEXIST) {
            return -1;
        }
        sprintf(shm_name_h, "shm%s", shm_name_h);
        fd_h = shm_open(shm_name_h, O_RDWR | O_CREAT | O_EXCL, 0666);
        if(fd_h < 0) {
            perror("h : shm_open()");
            return -1;
        }
    }
    shm_unlink(shm_name_h);
    printf("shm_open(%s)\n", shm_name_h);

    if(fd_c < 0) {
        perror("c : shm_open(c)");
        if(errno != EEXIST) {
            return -1;
        }
        sprintf(shm_name_c, "shm%s", shm_name_c);
        fd_c = shm_open(shm_name_c, O_RDWR | O_CREAT | O_EXCL, 0666);
        if(fd_c < 0) {
            perror("c : shm_open()");
            return -1;
        }
    }
    shm_unlink(shm_name_c);
    printf("shm_open(%s)\n", shm_name_c);

    if(fd_s < 0) {
        perror("s : shm_open()");
        if(errno != EEXIST) {
            return -1;
        }
        sprintf(shm_name_s, "shm%s", shm_name_s);
        fd_s = shm_open(shm_name_s, O_RDWR | O_CREAT | O_EXCL, 0666);
        if(fd_s < 0) {
            perror("s : shm_open()");
            return -1;
        }
    }
    shm_unlink(shm_name_s);
    printf("shm_open(%s)\n", shm_name_s);

    /* 3. 设置共享内存区对象的大小 */
    ret = ftruncate(fd_h, len_h);
    ret = ftruncate(fd_c, len_c);
    ret = ftruncate(fd_s, len_s);
    shm_h = mmap(NULL, len_h, PROT_WRITE | PROT_READ, MAP_SHARED, fd_h, 0);
    if(MAP_FAILED == shm_h) {
        perror("h : mmap()");
        return -1;
    }
    printf("mmap(h)\n");

    shm_c = mmap(NULL, len_c, PROT_WRITE | PROT_READ, MAP_SHARED, fd_c, 0);
    if(MAP_FAILED == shm_c) {
        perror("c : mmap()");
        munmap(shm_h, len_h);
        return -1;
    }
    printf("mmap(c)\n");

    shm_s = mmap(NULL, len_s, PROT_WRITE | PROT_READ, MAP_SHARED, fd_s, 0);
    if(MAP_FAILED == shm_s) {
        perror("s : mmap()");
        munmap(shm_h, len_h);
        munmap(shm_c, len_c);
        return -1;
    }
    printf("mmap(s)\n");


    /* 二值信号量，初始化保障 */
    /* 确保子进程处于sem_wait(sem_h)的阻塞状态 */
    /* 确保父进程一开始时可以生产，子进程一开始时就处于等待消费的状态 */
    int value;
    sem_getvalue(sem_h, &value);
    while(value != 0) {
        sem_wait(sem_h);
        sem_getvalue(sem_h, &value);
    }
    sem_getvalue(sem_c_prd, &value);
    while(value != 1) {
        sem_post(sem_c_prd);
        sem_getvalue(sem_c_prd, &value);
    }

    sem_getvalue(sem_s_prd, &value);
    while(value != 1) {
        sem_post(sem_s_prd);
        sem_getvalue(sem_s_con, &value);
    }

    sem_getvalue(sem_c_con, &value);
    while(value != 0) {
        sem_wait(sem_c_con);
        sem_getvalue(sem_c_con, &value);
    }

    sem_getvalue(sem_s_con, &value);
    while(value != 0) {
        sem_wait(sem_s_con);
        sem_getvalue(sem_s_con, &value);
    }

#ifdef FUNC
    printf("==========finish shm_sem_init()==========\n");
#endif
    return 0;
}

void posix_unmap_shm()
{
#ifdef FUNC
    printf("==========start unmap_shm()==========\n");
#endif
    munmap(shm_h, LEN_SHM + sizeof(int));
    munmap(shm_c, LEN_SHM + sizeof(int));
    munmap(shm_s, LEN_SHM + sizeof(int));
#ifdef FUNC
    printf("==========finish unmap_shm()==========\n");
#endif
}
#endif

//#ifdef SR04I
int sysv_sem_delete()
{
    semctl(semid, 0, IPC_RMID);
    //printf("semctl-rmid ok\n");
    return 0;
}

int sysv_shm_delete()
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
int sysv_shm_sem_init()
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
#ifdef DEBUG_SHM_SEM
    printf("semget() ok, semid = %d\n", semid);
#endif

    /* 2. 设置信号集中的所有信号量的初始值 */
    int i;
    union semun arg;
    /* 获取信号集，及其大小，设置信号集的初始化大小 */
    struct semid_ds ds;
    arg.buf = &ds;
    ret = semctl(semid, 0, IPC_STAT, arg);
#ifdef DEBUG_SHM_SEM
    printf("ds.sem_nsems = %ld\n", ds.sem_nsems);
    printf("arg.buf->sem_nsems = %ld\n", arg.buf->sem_nsems);
#endif
    arg.arry = (unsigned short *)calloc(arg.buf->sem_nsems, sizeof(unsigned short));

    arg.arry[SEM_H] = 0;
    arg.arry[SEM_C_PRD] = 1;
    arg.arry[SEM_C_CON] = 0;
    arg.arry[SEM_S_PRD] = 1;
    arg.arry[SEM_S_CON] = 0;
    ret = semctl(semid, 0, SETALL, arg);
    if(ret < 0) {
        perror("cannot semctl\n");
        return -1;
    }

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
#ifdef DEBUG_SHM_SEM
    printf("shm_h ok\n");
#endif

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
#ifdef DEBUG_SHM_SEM
    printf("shm_c ok\n");
#endif

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
#ifdef DEBUG_SHM_SEM
    printf("shm_s ok\n");
#endif

    shm_h = shmat(shmid_h, NULL, 0);
    if(shm_h == (void *)(-1)) {
        perror("shmat h");

        return -1;
    }
#ifdef DEBUG_SHM_SEM
    printf("shmat h ok\n");
#endif

    shm_c = shmat(shmid_c, NULL, 0);
    if(shm_c == (void *)(-1)) {
        perror("shmat c");
        return -1;
    }
#ifdef DEBUG_SHM_SEM
    printf("shmat c ok\n");
#endif

    shm_s = shmat(shmid_s, NULL, 0);
    if(shm_s == (void *)(-1)) {
        perror("shmat s");
        return -1;
    }
#ifdef DEBUG_SHM_SEM
    printf("shmat s ok\n");
#endif

    return 0;
}

/*
 * 使用二进制信号量
 * my_sempost(): 信号量值加1
 * my_semwait(): 等待信号量值变为1,然后值减1
 */
int sysv_my_semop(int semid, unsigned short sem_num, short op, short flag)
{
#ifdef DEBUG_SHM_SEM
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
#endif
    struct sembuf sops;
    sops.sem_num = sem_num;
    sops.sem_op = op;
    sops.sem_flg = flag;
    semop(semid, &sops, 1);
#ifdef DEBUG_SHM_SEM
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
#endif
    return 0;
}


/* wait: wait value become 0, do suff, make value 1 */
int sysv_my_semwait(int semid, unsigned short sem_num)
{
#ifdef FUNC
    printf("==========sysv_mysemwait()==========\n");
#endif
    return sysv_my_semop(semid, sem_num, -1, MY_SEM_BLOCK);
}

/* post: make value become 0 */
int sysv_my_sempost(int semid, unsigned short sem_num)
{
#ifdef FUNC
    printf("==========sysv_mysempost()==========\n");
#endif
    return sysv_my_semop(semid, sem_num, 1, MY_SEM_BLOCK);
}
//#endif

int get_shm_data_len(unsigned char *shm, int len_shm)
{
    int len = 0;
    memcpy(&len, shm, sizeof(int));
    if(len > len_shm - sizeof(int) || len < 0) {
#ifdef DEBUG_SHM_SEM
        printf("get_shm_data_len: length too long. %d > %d\n", len, len_shm);
#endif
        return -1;
    }
    else if(len == 0) {
#ifdef DEBUG_SHM_SEM
        printf("get_shm_data_len: len == 0, no data\n");
#endif
    }
    return len;
}


int write_to_shm(thread_arg_t *arg, int len_shm, char *fmt, ...)
{
#ifdef FUNC
    printf("==========start write_to_shm()==========\n");
#endif
    va_list ap;
    int len = 0;
    int len_tot = 0;
    int offset = 0;
    unsigned char *buff;
    char *fmt_tmp = fmt;

    /* 总长度检查 */
    va_start(ap, fmt);
    while(*fmt) {
        switch(*fmt++) {
            case 'l':
                len = va_arg(ap, int);
#ifdef DEBUG_SHM_SEM
                printf("write_to_shm: len = %d\n");
#endif
                len_tot += len;
#ifdef DEBUG_SHM_SEM
                printf("write_to_shm: len_tot = %d\n", len_tot);
#endif
                break;
            case 'd':
                buff = va_arg(ap, unsigned char *);
            default: 
                break;
        }
    }
#ifdef DEBUG_SHM_SEM
    printf("write_to_shm len_tot = %d\n", len_tot);
#endif
    va_end(ap);
    fmt = fmt_tmp;
    va_start(ap, fmt);

    /* 总长度符合*/
    if(len_tot <= len_shm && len_tot > 0) {
#ifdef OpenWrt
        sem_wait(arg->sem_prd);
#endif
        sysv_my_semwait(arg->semid, arg->sem_prd);
        memcpy(arg->shm, &len_tot, sizeof(int));
        offset += sizeof(len_tot);
        while(*fmt) {
            switch(*fmt++) {
                case 'l':
                    len = va_arg(ap, int);
                    break;
                case 'd':
                    buff = va_arg(ap, unsigned char *);
                    memcpy(arg->shm + offset, buff, len);
                    offset += len;
                    break;
                default:
                    break;

            }
        }
#ifdef OpenWrt
        sem_post(arg->sem_con);
#endif
        sysv_my_sempost(arg->semid, arg->sem_con);
    }
    /* 总长度不符合, 每个传入的串，但单独拷贝到共享内存 */
    else if(len_tot > len_shm) {
#ifdef DEBUG_SHM_SEM
        printf("write_to_shm: len_buff > len_shm, %d > %d\n", len_tot, len_shm);
#endif
        while(*fmt) {
            switch(*fmt++) {
                case 'l':
                    len = va_arg(ap, int);
                    break;
                case 'd':
                    {
                        int send = 0;
                        int left = len;
                        int tot_send = 0;
                        buff = va_arg(ap, unsigned char *);
                        while(left > 0) {
                            send = left<=len_shm?left:len_shm;
#ifdef OpenWrt
                            sem_wait(arg->sem_prd);
#endif
                            sysv_my_semwait(arg->semid, arg->sem_prd);
                            memcpy(arg->shm, &send, sizeof(send));
                            memcpy(arg->shm + sizeof(int), buff + tot_send, send);
#ifdef OpenWrt
                            sem_post(arg->sem_con);
#endif
                            sysv_my_sempost(arg->semid, arg->sem_con);
                            tot_send += send;
                            left -= send;
                        }
                        break;
                    }
                default:
                    break;
            }
        }

        /* 总长度OK */
        va_end(ap);
    }
    else {
#ifdef DEBUG_SHM_SEM
        printf("len is <=0 , wrong \n");
#endif
    }
#ifdef FUNC
    printf("==========finish write_to_shm()==========\n");
#endif
    return 0;
}

int shm_sem_init()
{
    return sysv_shm_sem_init();
#ifdef OpenWrt
    return posix_shm_sem_init();
#endif
}

void shm_sem_destory()
{
    sysv_sem_delete();
    sysv_shm_delete();
#ifdef OpenWrt
    /* 根据linux/unix系统编程手册P442 */
    //posix_unmap_shm();
#endif
}

int ssl_init(void)
{ 
#ifdef FUNC
    printf("==========start ssl_init()==========\n");
#endif
    SSL_load_error_strings();
    //OpenSSL_add_ssl_algorithms();
    SSLeay_add_ssl_algorithms();

    ctx_c = SSL_CTX_new(TLSv1_client_method());  //代理客户端
    if(!ctx_c) {
#ifdef DEBUG_SSL
        printf("cannot create ctx_c\n");
#endif
        return -1;
    }

    ctx_s = SSL_CTX_new(TLSv1_server_method());  //代理服务器
    if(!ctx_s) {
#ifdef DEBUG_SSL
        printf("cannot create ctx_s\n");
#endif
        return -1;
    }

    //SSL_CTX_set_verify(ctx_s, SSL_VERIFY_NONE, NULL);
    //SSL_CTX_set_verify(ctx_s, SSL_VERIFY_PEER, NULL);
    //SSL_CTX_load_verify_locations(ctx_s, ca_cert_file, NULL);
    if(SSL_CTX_use_certificate_file(ctx_s, server_cert_file, SSL_FILETYPE_PEM) <= 0) {
#ifdef DEBUG_SSL
        printf("cannot load server certificate file\n");
#endif
        return -1;
    }
    if(SSL_CTX_use_PrivateKey_file(ctx_s, private_key_file, SSL_FILETYPE_PEM) <= 0) {
#ifdef DEBUG_SSL
        printf("cannot load server private key file\n");
#endif
        return -1;
    }
    if(!SSL_CTX_check_private_key(ctx_s)) {
#ifdef DEBUG_SSL
        printf("cannot match server_cert_file and private_key_file\n");
#endif
        return -1;
    }
    //SSL_CTX_set_cipher_list(ctx_s, "RC4-MD5");
    //SSL_CTX_set_cipher_list(ctx_s, "AES256-GCM-SHA384");
    SSL_CTX_set_cipher_list(ctx_s, "ALL");
    SSL_CTX_set_mode(ctx_s, SSL_MODE_AUTO_RETRY);
#ifdef FUNC
    printf("==========finish ssl_init()==========\n");
#endif
    return 0;
}


int print_ssl_error(SSL *ssl, int ret)
{
    switch(SSL_get_error(ssl, ret)) {
        case SSL_ERROR_NONE:
            printf("ssl_error_none\n");
            return 0;
        case SSL_ERROR_ZERO_RETURN:
            printf("ssl_error_zero_return\n");
            break;
        case SSL_ERROR_WANT_READ:
            printf("ssl_error_want_read\n");
            break;
        case SSL_ERROR_WANT_WRITE:
            printf("ssl_error_want_write\n");
            break;
        case SSL_ERROR_WANT_CONNECT:
            printf("ssl_error_want_connect\n");
            break;
        case SSL_ERROR_WANT_ACCEPT:
            printf("ssl_error_want_accept\n");
            break;
        case SSL_ERROR_WANT_X509_LOOKUP:
            printf("ssl_error_want_x509_lookup\n");
            break;
            /*
               case SSL_ERROR_WANT_ASYNC:
               printf("ssl_error_want_async\n");
               break;
               case SSL_ERROR_WANT_ASYNC_JOB:
               printf("ssl_error_want_async_job\n");
               break;
               case SSL_ERROR_WANT_CLIENT_HELLO_CB:
               printf("ssl_error_want_client_hello_cb\n");
               break;
               */
        case SSL_ERROR_SYSCALL:
            printf("ssl_error_syscall\n");
            break;
        case SSL_ERROR_SSL:
            printf("ssl_error_ssl\n");
            break;
        default:
            printf("ssl_error_unknown\n");
            break;
    }
    return -1;
}


int handle_client()
{
#ifdef FUNC
    printf("==========start handle_client(%d)==========\n", getpid());
#endif
    /* 1. 父进程退出时收到SIGHUP信号 */
    if(prctl(PR_SET_PDEATHSIG, SIGHUP, 0, 0, 0) == -1) {
        printf("cannot prctl()");
    }

    /* 2. 注册信号处理函数 */
    if(signal(SIGPIPE, sig_handle_2) == SIG_ERR) {
        err_quit("signal()");
    }
    if(signal(SIGINT, sig_handle_2) == SIG_ERR) {
        err_quit("signal()");
    }

    /* 子进程一旦退出，立刻退出。子进程保证所有数据正常转发 */
    if(signal(SIGCHLD, sig_handle_2) == SIG_ERR) {
        err_quit("signal()");
    }
    if(signal(SIGHUP, sig_handle_2) == SIG_ERR) {
        err_quit("signal()");
    }

    /* 3. ssl初始化 */
    int ret;
    ssl_s = SSL_new(ctx_s);
    if(NULL == ssl_s) {
#ifdef DEBUG_SSL
        printf("cannot create ssl\n");
#endif
        return -1;
    }
#ifdef DEBUG_SSL
    printf("SSL_new ok\n");
#endif
    ret = SSL_set_fd(ssl_s, c_fd);
    if(ret != 1) {
#ifdef DEBUG_SSL
        printf("cannot SSL_set_fd()\n");
#endif
        print_ssl_error(ssl_s, ret);
        return -1;
    }
#ifdef DEBUG_SSL
    printf("SSL_set_fd ok\n");
#endif
    if((ret = SSL_accept(ssl_s)) == 0) {
#ifdef DEBUG_SSL
        printf("cannot SSL_accept()\n");
#endif
        print_ssl_error(ssl_s, ret);
        return -1;
    }
#ifdef DEBUG_SSL
    printf("SSL_accept ok\n");
#endif 

    /* 4. 信号量和共享内存初始化 */
    shm_sem_init();

    /* 5. 创建子进程，继承信号量＋共享内存 */
    pid_t child = fork();
    switch(child) {
        case -1:
            perror("handle_client, fork()");
            shm_sem_destory();
            exit(0);
        case 0:
            close(c_fd);
            SSL_free(ssl_s);
            SSL_CTX_free(ctx_s);
            ret = handle_server();
            exit(ret);
        default:
            break;
    }

    SSL_CTX_free(ctx_c);
    /* 6. 创建转发器线程 */
#ifdef OpenWrt
    thread_arg_t arg = {shm_s, ssl_s, fd_s, sem_s_prd, sem_s_con};
#endif
    thread_arg_t arg = {shm_s, ssl_s, semid, SEM_S_PRD, SEM_S_CON};
    pthread_t th;
    if(pthread_create(&th, NULL, (void *)do_forward, (void *)&arg) != 0) {
        perror("father, pthread_create()");
        shm_sem_destory();
        return -1;
    }

    /* 7. 读包－分析包－发包至转发器 */
#ifdef OpenWrt
    thread_arg_t arg_2 = {shm_c, ssl_s, fd_c, sem_c_prd, sem_c_con};
#endif
//#ifdef SR04I
    thread_arg_t arg_2 = {shm_c, ssl_s, semid, SEM_C_PRD, SEM_C_CON};
//#endif
    wake = 1;
    while((ret = read_process_to_shm(&arg_2)) > 0) ;

#ifdef DEBUG
    printf("handle_client: read_process_to_shm returned\n");
#endif
    /* a: 浏览器ssl握手后，毛线也没发就断开连接了,wake肯定为1
     * b: 若浏览器接收到了最后一个保报文,wake肯定为0.此时不能立刻退出进程
     *    要等数据服务器将数据发送至浏览器后再退出，这里用延时处理并不合适
     */
    if(ret == 0 && wake == 0) {
        sleep(TIMEOUT_CONNECT);
    }
    kill(child, SIGINT);
#ifdef DEBUG
    printf("handle_client read_process_to_shm exit\n");
#endif

    SSL_shutdown(ssl_s);
    close(c_fd);
    SSL_free(ssl_s);

    //共享内存和信号量的释放
    shm_sem_destory();

#ifdef FUNC
    printf("==========finish handle_client(%d)==========\n", getpid());
#endif
    return 0;
}


/*
 * do_forward: 把共享内存中的数据原样转发到对端
 * 在转发期间，要阻塞SIGCHLD信号
 */
void do_forward(void *ARG)
{
#ifdef FUNC
    printf("==========start do_forward(%d) from %d==========\n", getpid(), getppid());
#endif
    int len;
    int retval;
    pthread_detach(pthread_self());
    /*　传入参数 sem, ssl, shm */
    thread_arg_t *arg = (thread_arg_t *)ARG;
#ifdef DEBUG
    printf("===do_forward, sem_prd = %d, sem_con = %d\n", arg->sem_prd, arg->sem_con);
#endif
    while(1) {
#ifdef OpenWrt
        sem_wait(arg->sem_con);
#endif
//#ifdef SR04I
        sysv_my_semwait(arg->semid, arg->sem_con);
//#endif
        /*
        if(sigprocmask(SIG_BLOCK, &block_set, &pre_set) == -1) {
            perror("sigprocmask SIGCHLD");
        }
        */
        memcpy(&len, arg->shm, sizeof(int));
        printf("===do_foward_%d: len_shm = %d\n", getpid(), len);
        int tot_wr = 0;
        int actual_wr = 0;
        while(len - tot_wr > 0) {
            actual_wr = SSL_write(arg->ssl, arg->shm + sizeof(int) + tot_wr, len - tot_wr);
            tot_wr += actual_wr;
        }
        memset(arg->shm, 0, LEN_SHM + sizeof(int));
#ifdef OpenWrt
        sem_post(arg->sem_prd);
#endif
//#ifdef SR04I
        sysv_my_sempost(arg->semid, arg->sem_prd);
//#endif
        printf("===do_forward done once\n");
    }
    //free sources
#ifdef FUNC
    printf("==========finish do_forward(%d)==========\n", getpid());
#endif
    pthread_exit(&retval);
}


int handle_server()
{
#ifdef FUNC
    printf("==========start handle_server(%d)==========\n", getpid());
#endif
    /* 1. 父进程退出时收到SIGHUP信号 */
    if(prctl(PR_SET_PDEATHSIG, SIGHUP, 0, 0, 0) == -1) {
        printf("cannot prctl()");
    }

    /* 2. 注册信号处理函数 */
    if(signal(SIGPIPE, sig_handle) == SIG_ERR) {
        err_quit("signal()");
    }
    if(signal(SIGINT, sig_handle) == SIG_ERR) {
        err_quit("signal()");
    }
    if(signal(SIGHUP, sig_handle_2) == SIG_ERR) {
        err_quit("signal()");
    }

    /* 3. 等待唤醒消息 */
    int   ret;
    int   len;
    int   port;
    char  *host = (char *)malloc(LEN_HOST);
    memset(host, 0, LEN_HOST);
#ifdef OpenWrt
    ret = sem_wait(sem_h);
    if(ret < 0) {
        perror("sem_wait");
        return -1;
    }
#endif
//#ifdef SR04I
    ret = sysv_my_semwait(semid, SEM_H);
    if(ret < 0) {
        fprintf(stderr, "cannot sysv_my_semwait()\n");
        return -1;
    }
//#endif
    memcpy(&len, shm_h, sizeof(int));
    if(len <= 0) {
        printf("sem_wait(h) len = %d <= 0\n", len);
        return -1;
    }
    *(shm_h + sizeof(int) + len) = '\0';
    ret = sscanf((char *)shm_h + sizeof(int), "%[^:]:%d", host, &port);

    /* 4. 根据host来确定pcre2_code */
    re = get_re_by_host_port(regex_table, host, (short)port);
    if(NULL == re) {
        re = ge_re;
    }

    /* 5. 与服务器建立连接，绑定ssl */
    int s_fd = create_real_server_nonblock(host, port, TIMEOUT_CONNECT);
    if(s_fd < 0) {
#ifdef DEBUG
        printf("cannot create_real_server, %s:%d\n", host, (short)port);
#endif
        return -1;
    }
    SAFE_FREE(host);

    ssl_c = SSL_new(ctx_c);
    if(NULL == ssl_c) {
#ifdef DEBUG_SSL
        printf("cannot SSL_new ssl_c\n");
#endif
        return -1;
    }
#ifdef DEBUG_SSL
    printf("SSL_new ssl_c ok\n");
#endif
    ret = SSL_set_fd(ssl_c, s_fd);
    if(ret != 1) {
        print_ssl_error(ssl_c, ret);
        close(s_fd);
        return -1;
    }
#ifdef DEBUG_SSL
    printf("SSL_set_fd ssl_c ok\n");
#endif
    ret = SSL_connect(ssl_c);
    if(ret <= 0) {
        printf("cannot SSL_connect ssl_c\n");
        print_ssl_error(ssl_c, ret);
        close(s_fd);
        return -1;
    }
#ifdef DEBUG_SSL
    printf("SSL_connect ssl_c ok\n");
#endif

    /* 6. 建立转发器线程 */
#ifdef OpenWrt
    thread_arg_t arg = {shm_c, ssl_c, fd_c, sem_c_prd, sem_c_con};
#endif
//#ifdef SR04I
    thread_arg_t arg = {shm_c, ssl_c, semid, SEM_C_PRD, SEM_C_CON};
//#endif
    pthread_t th;
    if(pthread_create(&th, NULL, (void *)do_forward, (void *)&arg) < 0) {
        perror("child, pthread_create()");
        return -1;
    }

    /* 7. 读包－分析包－发包至转发器 */
#ifdef OpenWrt
    thread_arg_t arg_2 = {shm_s, ssl_c, fd_s, sem_s_prd, sem_s_con};
#endif
//#ifdef SR04I
    thread_arg_t arg_2 = {shm_s, ssl_c, semid, SEM_S_PRD, SEM_S_CON};
//#endif
    wake = 0;
    while((ret = read_process_to_shm(&arg_2)) > 0) ;

    /* 如果handle_server的read_process_to_shm() read 到0从while loop中break，那么等待do_forward之后直接退出 */
    /* 父进程的do_forward会在完成转发之后，sem_post(sem_prd) */
    /* important */
    if(ret == 0) {
//#ifdef SR04I
        sysv_my_semwait(arg_2.semid, arg_2.sem_prd);
//#endif
#ifdef OpenWrt
        sem_wait(arg_2.sem_prd);
#endif
    }

    /* 回收资源 */
    SSL_shutdown(ssl_c);
    close(s_fd);
    SSL_free(ssl_c);
#ifdef FUNC
    printf("==========finish handle_server(%d)==========\n", getpid());
#endif
    
    return ret;
}


/*
 * return: 
 *  <= 0 : failed
 *  > 0  : ok
 */
int read_process_to_shm(thread_arg_t *arg)
{
#ifdef FUNC
    printf("==========start read_process_to_shm(%d)==========\n", getpid());
#endif
    /* 1. 读http头 */
    int  ret;
    int  direction;
    short port;
    char *before_ip;
    char host[LEN_HOST] = {0};
    char buff_header[LEN_HEADER] = {0};
    ret = read_double_crlf(arg->ssl, buff_header, sizeof(buff_header) - 1);
    if(ret <= 0) {
#ifdef DEBUG
        printf("cannot read_double_crlf\n");
#endif
        return ret;
    }

    /* 2. 解析http头 */
    http_header_t *header = (http_header_t *)malloc(sizeof(http_header_t));
    memset(header, 0, sizeof(http_header_t));
    init_list_head(&(header->head));

    if(parse_http_header(buff_header, header) < 0) {
#ifdef DEBUG
        printf("cannot parse_http_header(%s)\n", buff_header);
#endif
        return -1;
    }

    /* 3. 获取host:port和before_ip */
    direction = is_http_req_rsp(header);
    if(direction == IS_REQUEST) {
        get_host_port(header, host, &port);  //替换前的ip
        before_ip = get_ip_before_remap(remap_table, host);
#ifdef DEBUG
        printf("is request\n");
        printf("get_host_port = %s:%d\n", host, port);
        printf("before_ip is %s\n", before_ip);
#endif
        if(before_ip == NULL) {
            re = ge_re;
        }
        else {
            if(regex_table == NULL || ((re = get_re_by_host_port(regex_table, before_ip, port)) == NULL)) {
                re = ge_re;
            }
        }
    }

    /* 4. 唤醒handle_server */
    if(1 == wake && direction == IS_REQUEST) {
        wake = 0;
        char addr[LEN_HOST + 6] = {0};
        sprintf(addr, "%s:%d", before_ip, port);
        int len = strlen(addr);
        memcpy(shm_h, &len, sizeof(int));
        memcpy(shm_h + sizeof(int), addr, len);
#ifdef OpenWrt
        sem_post(sem_h);
#endif
//#ifdef SR04I
        sysv_my_sempost(arg->semid, SEM_H);
//#endif
    }

    /* 5. 替换http头 */
    replace_http_header(header, re);
    //方案2性能更好，但不灵活，全替换
    //目前遇到的情况来看，可以使用全替换

    /* 6. 解析优先级，编码，长度信息 */
    int  pr;
    int  len;
    int  encd;
    len = get_pr_encd(&(header->head), &pr, &encd);

#ifdef DEBUG
    switch(pr) {
        case 0:
            printf("len = %d, PR_NONE,         encd = %d\n", len, encd);
            break;
        case 1:
            printf("len = %d, PR_TXT_CHUNK,    encd = %d\n", len, encd);
            break;
        case 2:
            printf("len = %d, PR_TXT_LEN,      encd = %d\n", len, encd);
            break;
        case 3:
            printf("len = %d, PR_NONE_TXT_LEN, encd = %d\n", len, encd);
            break;
        case 4:
            printf("len = %d, PR_NONE_TXT_CHK, encd = %d\n", len, encd);
            break;
        case 5:
            printf("len = %d, PR_TXT_NONE, encd = %d\n", len, encd);
            break;
        case 6:
            printf("len = %d, PR_Np NE_TXT_NONE, encd = %d\n", len, encd);
            break;
        default:
            break;
    }
    printf("len = %d, pr = %d, encd = %d\n", len, pr, encd);
    if(IS_REQUEST == direction) {
        printf("read is_request\n");
    }
    else if(IS_RESPONSE == direction) {
        printf("read is_response\n");
    }
#endif
    memset(buff_header, 0, sizeof(buff_header));
    /* 7. 根据优先级替换转发 */
    switch(pr) {
        int  ret;
        char *gunzip = NULL;
        PCRE2_SPTR new_body;
        unsigned int  len_gunzip = 0;

        case PR_TXT_LEN:
        {
#ifdef DEBUG
            printf("%d case %d:\n", getpid(), PR_TXT_LEN);
#endif
            /* read body */
            if(len <= 0) {
                /* post header */
                http_header_tostr(header, buff_header);
                write_to_shm(arg, LEN_SHM, "ld", strlen(buff_header), buff_header);
                break;
            }

            unsigned char *buf_body = (unsigned char *)malloc(len + 1);
            if(NULL == buf_body) {
                err_quit("malloc buf_body");
            }
            memset(buf_body, 0, len + 1);

            int n = readn(arg->ssl, buf_body, len);
#ifdef DEBUG
            printf("pr_txt_len: len = %d, read = %d\n", len, n);
#endif

            if(n < 0) {
#ifdef DEBUG
                printf("PR_CONTENT_LEN: read err\n");
#endif
                free_http_header(&header);
                return -1;
            }
            if(n == 0) {
                free_http_header(&header);
                return 0;
            }
            /* replace content */
            /* change content_length */
            /* send http header and body to handle_server */
            /*
             * 压缩
             *      解压成功
             *          替换成功：修改header(Content-length=new_body, Content-encoding)
             *          替换失败：修改header(Content-length=gunzip  , Content-encoding)
             erase_
             *      解压失败
             *          不修改header
             * 未压缩
             *      替换成功：修改header(Content-length)
             *      替换失败：不修改header
             */
            if(encd == ENCD_NONE) {
                /* 网页未压缩 */
                new_body = replace_content_default_m((char *)buf_body, direction, re);
                if(NULL == new_body) {
                    http_header_tostr(header, buff_header);
                    write_to_shm(arg, LEN_SHM, "ldld", strlen(buff_header), buff_header, n, buf_body);
                }
                else {
                    rewrite_clen_encd(&(header->head), strlen((char *)new_body), GZIP2GZIP);
                    http_header_tostr(header, buff_header);
                    write_to_shm(arg, LEN_SHM, "ldld", strlen(buff_header), buff_header, strlen((char *)new_body), new_body);
                }
            }

            else {
                /* 网页压缩,获取解压内容 */
                ret = -1;
                ret = get_gunzip(buf_body, n, &gunzip, &len_gunzip);
                if(ret == 0){
                    /* 解压成功 */
                    new_body = replace_content_default_m((char *) gunzip, direction, re);
                    if(NULL == new_body) {
                        /* 没有替换,发送原来的压缩数据 */
                        http_header_tostr(header, buff_header);
                        write_to_shm(arg, LEN_SHM, "ldld", strlen(buff_header), buff_header, n, buf_body);
                    }
                    else {
                        /* 替换成功，发送解压并替换后的包 */
                        rewrite_clen_encd(&(header->head), strlen((char *)new_body), GZIP2FLATE);
                        http_header_tostr(header, buff_header);
                        write_to_shm(arg, LEN_SHM, "ldld", strlen(buff_header), buff_header, strlen((char *)new_body), new_body);
                    }
                }
                else if(ret != 0 && encd == ENCD_GZIP) {
                    /* 解压失败 */
                    http_header_tostr(header, buff_header);
                    write_to_shm(arg, LEN_SHM, "ldld", strlen(buff_header), buff_header, n, buf_body);
                }
            }
            SAFE_FREE(gunzip);
            SAFE_FREE(new_body);
            SAFE_FREE(buf_body);
            break;
        }
        case PR_TXT_CHUNK:
        {
#ifdef DEBUG
            printf("%d case %d:\n", getpid(), PR_TXT_CHUNK);
#endif
            /* send header to handle_client */
            /* loop: read, replace and send to handle_server */
            if(encd == ENCD_FLATE)
            {
                /* 未压缩 */
                http_header_tostr(header, buff_header);
                write_to_shm(arg, LEN_SHM, "ld", strlen(buff_header), buff_header);
                forward_http_chunked(arg, LEN_SHM, encd, direction, re);
            }
            else if(encd == ENCD_GZIP)
            {
                /* 压缩 */
                int    m = -1;
                char   chunk_size[64] = {0};
                unsigned int len_chunk  = 0;
                unsigned char *all_chunk = NULL;
                m = get_all_chunk_m(arg->ssl, &all_chunk, &len_chunk);
                if(m != 0)
                {
#ifdef DEBUG
                    printf("get_all_chunk failed\n");
#endif
                    break;
                }
                ret = -1;
                ret = get_gunzip(all_chunk, len_chunk, &gunzip, &len_gunzip);
                if(ret == 0)
                {
                    /* 解压成功 */
                    rewrite_c_encd(&(header->head), ENCD_FLATE);
                    new_body = replace_content_default_m(gunzip, direction, re);
                    if(new_body)
                    {
                        /* 替换成功 */
                        sprintf(chunk_size, "%x\r\n", strlen((char *)new_body));
                        http_header_tostr(header, buff_header);
                        write_to_shm(arg, LEN_SHM, "ldldldld",
                                strlen(buff_header), buff_header,
                                strlen(chunk_size), chunk_size,
                                strlen((char *)new_body), new_body,
                                7, "\r\n0\r\n\r\n");
                        SAFE_FREE(new_body);
                    }
                    else
                    {
                        /* 未替换 */
                        sprintf(chunk_size, "%x\r\n", len_gunzip);
                        http_header_tostr(header, buff_header);
                        write_to_shm(arg, LEN_SHM, "ldldldld",
                                strlen(buff_header), buff_header,
                                strlen(chunk_size), chunk_size,
                                len_gunzip, gunzip,
                                7, "\r\n0\r\n\r\n");
                    }
                }
                else
                {
                    /* 解压失败 */
                    sprintf(chunk_size, "%x\r\n", len_chunk);
                    http_header_tostr(header, buff_header);
                    write_to_shm(arg, LEN_SHM, "ldldldld",
                            strlen(buff_header), buff_header,
                            strlen(chunk_size), chunk_size,
                            len_chunk, all_chunk,
                            7, "\r\n0\r\n\r\n");
                }
                SAFE_FREE(gunzip);
                SAFE_FREE(all_chunk);
            }
            break;
        }

        case PR_NONE_TXT_LEN:
        {
#ifdef DEBUG
            printf("%d case %d:\n", getpid(), PR_NONE_TXT_LEN);
#endif
            http_header_tostr(header, buff_header);
            write_to_shm(arg, LEN_SHM, "ld", strlen(buff_header), buff_header);
            printf("pr_none_txt_len: len = %d\n", len);
            if(len <= 0) {
                break;
            }

            ret = read_forward_none_txt(arg, LEN_SHM, len, "pr_none_txt_len");
            if(ret <= 0) {
                free_http_header(&header);
                return ret;
            }
            break;
        }
        case PR_NONE_TXT_CHK:
        {
#ifdef DEBUG
            printf("%d case %d:\n", getpid(), PR_NONE_TXT_CHK);
#endif
            int ava;
            int tot;
            int left;
            int read;
            int real_read;
            unsigned int size;
            char crlf[2] = {0};
            char chunk_size[64] = {0};
            http_header_tostr(header, buff_header);
            write_to_shm(arg, LEN_SHM, "ld", strlen(buff_header), buff_header);
            /* 循环转发chunk */
            while(1) {
                read_line(arg->ssl, chunk_size, sizeof(chunk_size));
                write_to_shm(arg, LEN_SHM, "ld", strlen(chunk_size), chunk_size);
                erase_nhex(chunk_size);
                hex2dec(chunk_size, &size);
#ifdef DEBUG
                printf("chunk_size = %d\n", size);
#endif
                tot  = 0;
                ava  = LEN_SHM;
                left = size + 2;  //2 is for "\r\n", NUM1\r\nBODY1\r\nNUM2\r\nBODY2\r\n 0\r\n\r\n

                ret = read_forward_none_txt(arg, LEN_SHM, left, "pr_none_txt_chk");
                if(ret <= 0) {
                    free_http_header(&header);
                    return ret;
                }
                if(size == 0) {
                    break;
                }
            }
            break;
        }

        case PR_TXT_NONE:
        {
#ifdef DEBUG
            printf("%d case %d: pr_txt_none\n", getpid(), PR_TXT_NONE);
#endif
            /* handle: 对端发送完最后一个报文后关闭写，不管是request还是response */
            /* 可能有body, 全部接收，替换转发 */
            int  ava;
            int  whole;
            int  offset;
            int  real_read;
            char body[LEN_BODY] = {0};
            whole = 1;
            offset = 0;
            ava = LEN_BODY;
#ifdef DEBUG
            printf("%d case %d: pr_txt_none, will in while loop\n", getpid(), PR_TXT_NONE);
#endif
            while(1) {
                real_read = SSL_read(arg->ssl, body + offset, ava);
                if(real_read < 0) {
                    perror("SSL_read");
                    free_http_header(&header);
#ifdef DEBUG
                    printf("%d case %d: pr_txt_none, will return -1\n", getpid(), PR_TXT_NONE);
#endif
                    return -1;
                }
                else if(real_read == 0) {
                    //先替换转发，然后再return.
                    if(offset > 0) {
                        forward_txt(header, body, offset, whole, encd, arg, LEN_SHM, direction, re);
                    }
                    free_http_header(&header);
#ifdef DEBUG
                    printf("%d case %d: pr_txt_none, will return 0, offset = %d\n", getpid(), PR_TXT_NONE, offset);
#endif
                    return 0;
                }
                else {
                    ava    -= real_read;
                    offset += real_read;
                    if(ava == 0) {
                        offset = 0;
                        ava = LEN_BODY;
                        if(whole == 1) {
                            http_header_tostr(header, buff_header);
                            write_to_shm(arg, LEN_SHM, "ld", strlen(buff_header), buff_header);
                        }
                        whole = 0;
                        forward_txt(header, body, offset, whole, encd, arg, LEN_SHM, direction, re);
                        memset(body, 0, sizeof(body));  //unnecessary
                    }
                }
            }
#ifdef DEBUG
            printf("%d case %d: pr_txt_none, will break\n", getpid(), PR_TXT_NONE);
#endif
            break;
        }

        case PR_NONE_TXT_NONE:
        {
#ifdef DEBUG
            printf("%d case %d: pr_none_txt_none\n", getpid(), PR_NONE_TXT_NONE);
#endif
            /* handle: 对端发送完最后一个报文后关闭写，不管是request还是response */
            http_header_tostr(header, buff_header);
            write_to_shm(arg, LEN_SHM, "ld", strlen(buff_header), buff_header);
            //free_http_header(&header);
            if(IS_REQUEST == direction) {
#ifdef DEBUG
                printf("PR_NONE_TXT_NONE: is_request\n");
#endif
                break;
            }
            else if(IS_RESPONSE == direction) {
#ifdef DEBUG
                printf("PR_NONE_TXT_NONE: is_response\n");
#endif
            }
            /* 可能有body,接收转发,长度未知 */
            while((ret = read_forward_none_txt(arg, LEN_SHM, LEN_SHM, "pr_none_txt_none")) == 1) ;
            if(ret <= 0) {
                free_http_header(&header);
                return ret;
            }
            break;
        }

        case PR_NONE:
        default:
        {
#ifdef DEBUG
            printf("%d case %d: pr_none\n", getpid(), pr);
#endif
            http_header_tostr(header, buff_header);
            write_to_shm(arg, LEN_SHM, "ld", strlen(buff_header), buff_header);
            break;
        }
    }
    free_http_header(&header);
#ifdef FUNC
    printf("==========finish read_process_to_shm(%d)==========\n", getpid());
#endif
    return 1;
}

/* 后期优化: 使用链表处理 */
int get_all_chunk_m(SSL *ssl, unsigned char **all_chunk, unsigned int *len)
{
#ifdef FUNC
    printf("==========start get_all_chunk_m()==========\n");
#endif
    int    n = 0;
    char   crlf[2];
    char   s_size[64] = {0};
    unsigned int size = 0;
    unsigned int tot = 0;
    unsigned char *data = (unsigned char *)calloc(1, 1);
    unsigned char *tmp  = NULL;
    while(1)
    {
        if((n = read_line(ssl, s_size, sizeof(s_size))) <= 0)
            return -1;
#ifdef DEBUG
        printf("[0x%s]\n", s_size);
#endif
        erase_nhex(s_size);
        hex2dec(s_size, &size);
        memset(s_size, 0, sizeof(s_size));
        if(size > 0)
        {
            tmp = (unsigned char *)calloc(1, tot + size);
            memcpy(tmp, data, tot);
            SAFE_FREE(data);
            data = tmp; 
            /* read data and \r\n */
            readn(ssl, data + tot, size);
            readn(ssl, crlf, 2);
            tot += size;
#ifdef DEBUG
            printf("get_all_chunk tot=%d\n", tot);
#endif
        }
        else if(size == 0) {
            /* no data but has \r\n */
            n = readn(ssl, crlf, 2);
            break;
        }
    }
    *all_chunk = data;
    *len = tot;
#ifdef FUNC
    printf("==========finish get_all_chunk_m()==========\n");
#endif
    return 0;
}

/*
 * 优化方案已经想好，接口名无需修改，暂不优化，先调通程序
 */
int forward_http_chunked(thread_arg_t *arg, int len_shm, int encd, int direction, pcre2_code *re)
{
    /* 思路：开个大buff接收，满则替换转发，未满则接续接收 */
    /* 此函数只用于转发未压缩的chunked文本http报文 */
#ifdef FUNC
    printf("==========start forward_http_chunked()==========\n");
#endif
    char s_size[64] = {0};
    uint32_t size = 0;
    uint32_t n, m;
    char buff[LEN_CHUNK];
    char *ptr = buff;
    /* size_t tot_buf = 0; */
    int left = sizeof(buff);
    int size_flag = 1;
    while(encd == ENCD_FLATE)
    {
        if(size_flag)
        {
            if((n = read_line(arg->ssl, s_size, sizeof(s_size))) <= 0)
                break;
#ifdef DEBUG
            printf("[0x%s]\n", s_size);
#endif
            erase_nhex(s_size);
            hex2dec(s_size, &size);
#ifdef DEBUG
            printf("read chunked size = %d\n", size);
#endif
        }
        /* chunk_data + "\r\n" */
        /* BUG: 第一次size > LEN_CHUNK, 会造成死循环 */
        if(size + 2 <= left && size > 0)
        {
            if((n = readn(arg->ssl, ptr, size + 2)) > 0)
            {
#ifdef DEBUG
                printf("n=%d\n", n);
#endif
                ptr += (n - 2);
                left -= (n - 2);
                size_flag = 1;  /* 读完chunked正文后,肯定要读取一下chunked的size */
            }
            else
            {
                /* 出错处理:缓冲区中可能有数据，需要将其转发掉，然后退出循环 */
                size_flag = 0;
                size = 0;
            }
        }
        else
        {
            size_flag = 0;
            /* 替换转发 */
            char chunk_size[64] = {0};
            PCRE2_SPTR new_chunked = replace_content_default_m(buff, direction, re);
            if(new_chunked)
            {
                int new_size = strlen((char *) new_chunked);
                sprintf(chunk_size, "%x\r\n", new_size);
#ifdef DEBUG
                printf("\033[33m");
                printf("replace, new chunked size=%s\n", chunk_size);
                printf("\033[0m");
#endif
                write_to_shm(arg, len_shm, "ldldld", strlen(chunk_size), chunk_size, strlen((char *)new_chunked), new_chunked, 2, "\r\n");
                SAFE_FREE(new_chunked);
            }
            else
            {
                sprintf(chunk_size, "%x\r\n", LEN_CHUNK - left);
#ifdef DEBUG
                printf("\033[33m");
                printf("no replace, new chunked size=%s\n", chunk_size);
                printf("\033[0m");
#endif
                write_to_shm(arg, len_shm, "ldldld", strlen(chunk_size), chunk_size, (LEN_CHUNK - left), buff, 2, "\r\n");
            }
            /* 一次替换转发结束 */
            memset(buff, 0, sizeof(buff));
            left = sizeof(buff);
            ptr = buff;
            if(size == 0)
                break;
        }
    }

    write_to_shm(arg, len_shm, "ldld", 5, "0\r\n\r\n");
    /* 转发chunk后的拖挂内容 一般是补充的域(field)信息
     * 如果包含拖挂内容,拖挂内容的长度是无法确定的,Keep-alive就会引起问题,这里:舍弃拖挂内容
     while((n = read(s_fd, buff, sizeof(buff))) > 0)
     m = write(c_fd, buff, n);
     */
#ifdef FUNC
    printf("==========finish forward_http_chunked()==========\n");
#endif
    return 0;
}

int forward_txt(http_header_t *header, unsigned char *body, int len, int whole, int encd, thread_arg_t *arg, int len_shm, int direction, pcre2_code *re)
{
#ifdef FUNC
    printf("==========start forward_txt()==========\n");
#endif
    int ret;
    char *gunzip;
    int len_gunzip;
    char buff_header[LEN_HEADER] = {0};
    PCRE2_SPTR new_body = NULL;
    int df;
#ifdef DEBUG
    printf("len = %d, whole = %d, encd = %d\n", len, whole, encd);
#endif

    /* 不完整的包不用转header */
    if(whole != 1) {
        /*  不完整的压缩包，直接转 */
        if(encd == ENCD_GZIP) {
#ifdef DEBUG
            printf("not whole, direct forwrad, gunzip\n");
#endif
            write_to_shm(arg, len_shm, "ld", len, body);
        }
        else {
            new_body = replace_content_default_m(body, direction, re);
            if(new_body) {
#ifdef DEBUG
                printf("not whole, forward replace\n");
#endif
                write_to_shm(arg, len_shm, "ld", strlen((char *)new_body), new_body);
                SAFE_FREE(new_body);
            }
            else {
#ifdef DEBUG
                printf("not whole, direct forwrad txt no replace\n");
#endif
                write_to_shm(arg, len_shm, "ld", len, body);
            }
        }
    }

    /* 完整的包还要转一下header */
    else {
        if(encd == ENCD_GZIP) {
            /* 整包就解压 */
            ret = get_gunzip(body, len, &gunzip, &len_gunzip);
            if(ret < 0) {
#ifdef DEBUG
                printf("whole, direct forwrad, cannot gunzip\n");
#endif
                http_header_tostr(header, buff_header);
                write_to_shm(arg, len_shm, "ldld", strlen(buff_header), buff_header, len, body); 
            }
            else {
                /* need to rewrite_encd */
                new_body = replace_content_default_m(gunzip, direction, re);
                if(new_body) {
#ifdef DEBUG
                    printf("whole, forward new_body");
#endif
                    rewrite_c_encd(&(header->head), ENCD_FLATE);
                    http_header_tostr(header, buff_header);
                    write_to_shm(arg, len_shm, "ldld", strlen(buff_header), buff_header, strlen((char *)new_body), new_body);
                }
                else 
#ifdef DEBUG
                    printf("whole, direct forwrad, cannot replace\n");
#endif
                http_header_tostr(header, buff_header);
                write_to_shm(arg, len_shm, "ldld", strlen(buff_header), buff_header, len, body); 
            }
            SAFE_FREE(gunzip);
            SAFE_FREE(new_body);
        }

        else {
            http_header_tostr(header, buff_header);
            new_body = replace_content_default_m(body, direction, re);
            if(new_body) {
#ifdef DEBUG
                printf("whole, forward new_body");
#endif
                write_to_shm(arg, len_shm, "ldld", strlen(buff_header), buff_header, strlen((char *)new_body), new_body);
                SAFE_FREE(new_body);
            }
            else {
#ifdef DEBUG
                printf("whole, direct forwrad, cannot replace\n");
#endif
                write_to_shm(arg, len_shm, "ldld", strlen(buff_header), buff_header, len, body);
            }
        }
    }

#ifdef FUNC
    printf("==========finish forward_txt()==========\n");
#endif
    return 1;
}

/* 
 * return :
 *      1 : 读并转发完成
 *      0 : 读到结束,(非信号打断错误) 
 *      -1: 读到错误 
 */
int read_forward_none_txt(thread_arg_t *arg, int len_shm, int len_body, const char *comment)
{
#ifdef FUNC
    printf("==========start read_forward_none_txt==========\n");
#endif
    int tot;
    int ava;
    int left;
    int read;
    int real_read;
    tot = 0;
    ava = len_shm;
    left = len_body;
#ifdef DEBUG
    printf("%s: read_forward_none_txt: len_body = %d\n", comment, len_body);
#endif
    /* 直接读进共享内存 */
#ifdef OpenWrt
    sem_wait(arg->sem_prd);
#endif
//#ifdef SR04I
    sysv_my_semwait(arg->semid, arg->sem_prd);
//#endif
    while(left > 0) {
        read = left<=ava?left:ava;
        real_read = SSL_read(arg->ssl, arg->shm + sizeof(int) + tot, read); 
#ifdef DEBUG
        printf("%s: read_forward_none_txt: real_read = %d\n", comment, real_read);
#endif
        if(real_read < 0) {
            perror("SSL_read()");
            if(errno == EINTR) {
                continue;
            }
            else {
                return -1;
            }
        }
        else if(real_read == 0) {
            break;
        }
        else {
            tot    += real_read;
            left   -= real_read;
            ava    -= real_read;

            if(ava == 0) {
                memcpy(arg->shm, &tot, sizeof(tot));
#ifdef DEBUG
                printf("%s: read_forward_none_txt: tot = %d, still has left\n", comment, tot);
#endif
                tot = 0;
                ava = len_shm;
#ifdef OpenWrt
                sem_post(arg->sem_con);
#endif
//#ifdef SR04I
                sysv_my_sempost(arg->semid, arg->sem_con);
//#endif
#ifdef OpenWrt
                sem_wait(arg->sem_prd);
#endif
//#ifdef SR04I
                sysv_my_semwait(arg->semid, arg->sem_prd);
//#endif

            }
        }
    }
    memcpy(arg->shm, &tot, sizeof(int));
#ifdef DEBUG
    printf("%s: tot = %d, no left\n", comment, tot);
#endif
#ifdef OpenWrt
    sem_post(arg->sem_con);
#endif
//#ifdef SR04I
    sysv_my_sempost(arg->semid, arg->sem_con);
//#endif

#ifdef FUNC
    printf("==========finish read_forward_none_txt==========\n");
#endif
    return real_read;
}


int create_proxy_server(char *host, short l_port, int listen_num)
{
#ifdef FUNC
    printf("==========start create_proxy_server()==========\n");
#endif
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0)
        err_quit("socket");
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));

    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(l_port);
    if(NULL == host) {
        local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } 
    inet_pton(AF_INET, host, &local_addr.sin_addr.s_addr);
    if(bind(fd, (struct sockaddr *) &local_addr, sizeof(local_addr)) < 0)
        err_quit("bind");
    if(listen(fd, listen_num) < 0)
        err_quit("listen");
#ifdef FUNC
    printf("==========finish create_proxyy_server()==========\n");
#endif
    return fd;
}

int create_real_server(const char *host, short port)
{
    /* 建立和服务器的连接, 使用select超时连接 */
#ifdef FUNC
    printf("==========start create_real_server()==========\n");
#endif
#ifdef DEBUG
    printf("create_real_server host=%s, port=%d\n", host, port);
#endif
    int s_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(s_fd < 0)
        err_quit("socket");
    struct sockaddr_in server_addr;
    struct hostent *server;
    if((server = gethostbyname(host)) == NULL)
    {
#ifdef DEBUG
        printf("\033[31m");
        printf("gethostbyname %s error, h_error=%d, %s\n", host, h_errno, hstrerror(h_errno));
        printf("\033[0m");
#endif
        return -1;
    }
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    //inet_pton(AF_INET, host, &(server_addr.sin_addr.s_addr));
    memcpy(&(server_addr.sin_addr.s_addr), server->h_addr, server->h_length);
    char ip[LEN_IP] = {0};
    if(connect(s_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0)
        err_quit("connect");
#ifdef DEBUG
    printf("%s  %s port=%d\n", host, inet_ntop(AF_INET, server->h_addr, ip, sizeof(ip)), port);
    printf("connected to %s:%d\n", host, port);
#endif
#ifdef FUNC
    printf("==========finish create_real_server()==========\n");
#endif
    return s_fd;
}

int create_real_server_nonblock(const char *host, short port, int sec)
{
    /* 建立和服务器的连接 */
#ifdef FUNC
    printf("==========start create_real_server_nonblock()==========\n");
#endif
    int s_fd = socket(AF_INET, SOCK_STREAM, 0);

    if(s_fd < 0)
        err_quit("socket");
    /* 设置非阻塞 */
    int flags = fcntl(s_fd, F_GETFL, 0);
    if(flags < 0)
    {
        perror("fcntl f_get");
        goto end;
    }
    if(fcntl(s_fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        perror("fcntl f_set");
        goto end;
    }

    struct sockaddr_in server_addr;
    struct hostent *server;
    if((server = gethostbyname(host)) == NULL)
    {
        printf("\033[31m");
        printf("gethostbyname [%s] error, h_error=%d, %s\n", host, h_errno, hstrerror(h_errno));
        printf("\033[0m");
        goto end;
    }
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    /* inet_pton(AF_INET, host, &(server_addr.sin_addr.s_addr)); */
    memcpy(&(server_addr.sin_addr.s_addr), server->h_addr, server->h_length);
    char ip[16] = {0};
#ifdef DEBUG
    printf("%s <--> %s port=%d\n", host, inet_ntop(AF_INET, server->h_addr, ip, sizeof(ip)), port);
#endif
    if(connect(s_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0)
    {
        if(errno != EINPROGRESS)
        {
#ifdef DEBUG
            printf("connect err\n");
#endif
            goto end;
        }
    }
    fd_set rset, wset;
    FD_ZERO(&rset);
    FD_ZERO(&wset);
    FD_SET(s_fd, &rset);
    FD_SET(s_fd, &wset);
    struct timeval tout;
    tout.tv_sec = sec > 0 ? sec : 0;
    tout.tv_usec = 0;
    int ret = select(s_fd + 1, &rset, &wset, NULL, tout.tv_sec > 0 ? &tout : NULL);
    if(ret > 0)
    {
        if(FD_ISSET(s_fd, &rset) || FD_ISSET(s_fd, &wset))
        {
            int error = 0;
            unsigned int len = sizeof(error);
            if(getsockopt(s_fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
            {
                perror("getsockopt");
                goto end;
            }
            else
            {
                /* 改回非阻塞 */
                if(fcntl(s_fd, F_SETFL, flags) < 0)
                    goto end;
                return s_fd;
            }
        }
    }
    else if(ret == 0)
    {
#ifdef DEBUG
        printf("select timeout!\n");
#endif
        goto end;
    }
    else
    {
        perror("select");
        goto end;
    }

end:
    close(s_fd);
#ifdef FUNC
    printf("==========finish create_real_server_nonblock()==========\n");
#endif
    return -1;
}



PCRE2_SPTR replace_content_default_m(char *old, int direction, pcre2_code *re)
{
#ifdef x86
    return NULL;
#endif
#ifdef FUNC
    printf("==========start replace_content_default_m()==========\n");
#endif
    PCRE2_SPTR new;
    struct list_head *head = get_list_substring_compiled_code((PCRE2_SPTR) old, re);
    if(head == NULL)
        return NULL;
    if(direction == REQUEST)
        pad_list_rplstr_malloc(head, pad_list_rplstr_remap_table_req_m, remap_table);
    else if(direction == RESPONSE)
        pad_list_rplstr_malloc(head, pad_list_rplstr_remap_table_rsp_m, remap_table);
    /* pad_list_rplstr_malloc(head, pad_list_rplstr_remap_table_rsp_m, remap_table); */
    new = replace_all_default_malloc((PCRE2_SPTR) old, head);
    free_list_substring(&head);
#ifdef FUNC
    printf("==========finish replace_content_default_m（）==========\n");
#endif
    if(NULL == new)
        return NULL;
    return new;
}


int rewrite_url(char *url, pcre2_code *re)
{
    /* 替换ip */
#ifdef FUNC
    printf("==========start rewrite_url()==========\n");
#endif
    int len;
    PCRE2_SPTR subject = replace_content_default_m(url, IS_REQUEST, re);
    if(subject)
    {
        len = strlen((char *)subject);
        memmove(url, (char *)subject, strlen((char *)subject));
        *(url + len) = '\0';
        SAFE_FREE(subject);
    }

    /* 重写格式 */
    char *p = strstr(url, "http://");
    if(p)
    {
        char *p1 = strchr(p + 7, '/');
        if(p1)
        {
            /* http://192.168.1.33/setup.cgi?ip1=192.168.1.33&ip2=192.168.1.22  --> /setup.cgi?ip1=192.168.1.33&ip2=192.168.1.22 */
            len = strlen(p1);
            memmove(url, p1, strlen(p1));
            *(url + len) = '\0';
        }
        else
        {
            /* http://192.168.1.33 --> / */
            memset(url, 0, LEN_URL);
            strcpy(url, "/");
        }
    }
    //printf("after rewrite url=%s\n", req->url);
#ifdef FUNC
    printf("==========finish rewrite_url()==========\n");
#endif
    return 0;
}


int replace_field(char *field_value, int direction, pcre2_code *re)
{
#ifdef FUNC
    printf("==========start replace_field()==========\n");
#endif
    PCRE2_SPTR subject = (PCRE2_SPTR) field_value;
    struct list_head *head = get_list_substring_compiled_code(subject, re);
    if(head == NULL)
        return -1;

    if(direction == REQUEST)
        pad_list_rplstr_malloc(head, pad_list_rplstr_remap_table_req_m, remap_table);
    else if(direction == RESPONSE)
        pad_list_rplstr_malloc(head, pad_list_rplstr_remap_table_rsp_m, remap_table);
    PCRE2_SPTR new_subject = replace_all_default_malloc(subject, head);
    if(NULL == new_subject)
    {
        free_list_substring(&head);
        return -1;
    }
    memset(field_value, 0, LEN_FIELD_VALUE);
    strcpy(field_value, (char *) new_subject);
    free_list_substring(&head);
    SAFE_FREE(new_subject);
#ifdef FUNC
    printf("==========finish replace_field()==========\n");
#endif
    return 0;
}

/* 
 * 
 */
//int rewrite_http_header(struct list_head *head, int direction, pcre2_code *re)
int replace_http_header(http_header_t *header, pcre2_code *re)
{
#ifdef FUNC
    printf("==========start replace_http_header()==========\n");
#endif
    int direction = is_http_req_rsp(header);
    /* replace url */
    if(direction == IS_REQUEST) {
        rewrite_url(header->url, re);
    }
    /* 使用get方法时 GET /setup.cgi?ip=192.168.1.1&port=8080提交的表单数据不应该被替换 */
    struct list_head *head = &(header->head);
    struct list_head *pos = NULL;
    list_for_each(pos, head)
    {
        http_field_t *field = list_entry(pos, http_field_t, list);

        if(strcasecmp(field->key, "Host") == 0)
        {
#ifdef DEBUG
            printf("<%s>\n", field->key);
#endif
            replace_field(field->value, direction, re);
        }
        if(strcasecmp(field->key, "Referer") == 0)
        {
#ifdef DEBUG
            printf("<%s>\n", field->key);
#endif
            replace_field(field->value, direction, re);
        }
        if(strcasecmp(field->key, "Origin") == 0)
        {
#ifdef DEBUG
            printf("<%s>\n", field->key);
#endif
            replace_field(field->value, direction, re);
        }
        if(strcasecmp(field->key, "Location") == 0)
        {
#ifdef DEBUG
            printf("<%s>\n", field->key);
#endif
            replace_field(field->value, direction, re);
        }
    }
#ifdef FUNC
    printf("==========finish replace_http_header()==========\n");
#endif
    return 0;
}

int get_gunzip(unsigned char *src, unsigned int len_s, char **dst, unsigned int *len_d)
{
#ifdef FUNC
    printf("==========start get_gunzip==========\n");
#endif
    int ret;
    srandom(time(NULL));
    char tmp[64] = {0};
    char tmp_gz[64] = {0};
    char cmd[256] = {0};
    long r1 = random();
    long r2 = random();
    sprintf(tmp, "/tmp/%ld%ld", r1, r2);
    sprintf(tmp_gz, "%s.gz", tmp);
    int fd_s = open(tmp_gz, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if(fd_s < 0)
        return -1;
    if(write(fd_s, src, len_s) != len_s)
    {
        close(fd_s);
        unlink(tmp_gz);
        return -1;
    }

    close(fd_s);
    sprintf(cmd, "gunzip %s", tmp_gz);                       
    sighandler_t old_handler = signal(SIGCHLD, SIG_DFL);
    ret = system(cmd);
    signal(SIGCHLD, old_handler);
    unlink(tmp_gz);                                          /* not necessary */

    int fd_d = open(tmp, O_RDONLY);
    if(fd_d < 0)
        return -1;
    *len_d = lseek(fd_d, 0, SEEK_END);
    lseek(fd_d, 0, SEEK_SET);
    *dst = (char *)calloc(1, *len_d);
    if(NULL == *dst)
    {
        perror("malloc");
        close(fd_d);
        unlink(tmp); 
        return -1;
    }
    if(read(fd_d, *dst, *len_d) != *len_d)
    {
        SAFE_FREE(*dst);
        close(fd_d);
        unlink(tmp); 
        return -1;
    }
    close(fd_d);
    unlink(tmp);
#ifdef FUNC
    printf("==========finish get_gunzip()==========\n");
#endif
    return 0;
}

/* 信号处理函数 */
void sig_handle(int signo)
{
#ifdef FUNC
    printf("==========start sig_handle()==========\n");
#endif
    if(signo == SIGCHLD){
#ifdef DEBUG
        printf("%d capture SIGCHLD\n", getpid());
#endif
        pid_t pid;
        while((pid = wait(NULL)) > 0)
        {
#ifdef DEBUG
            printf("wait %d\n", pid);
#endif
        }
    }
    else if(signo == SIGPIPE)
    {
#ifdef DEBUG
        printf("%d capture SIGPIPE\n", getpid());
#endif
        exit(1);
    }
    else if(signo == SIGINT)
    {
#ifdef DEBUG
        printf("%d capture SIGINT\n", getpid());
#endif
        exit(1);
    }
#ifdef FUNC
    printf("==========finish sig_handle()==========\n");
#endif
}


void sig_handle_2(int signo)
{
#ifdef FUNC
    printf("==========start sig_handle()==========\n");
#endif
    if(signo == SIGCHLD){
#ifdef DEBUG
        printf("%d capture SIGCHLD\n", getpid());
#endif
        pid_t pid;
        while((pid = wait(NULL)) > 0)
        {
#ifdef DEBUG
            printf("%d wait %d\n", getpid(), pid);
#endif
        }
    }
    else if(signo == SIGPIPE)
    {
#ifdef DEBUG
        printf("%d capture SIGPIPE\n", getpid());
#endif
    }
    else if(signo == SIGINT)
    {
#ifdef DEBUG
        printf("%d capture SIGINT\n", getpid());
#endif
    }
    else if(signo == SIGHUP)
    {
#ifdef DEBUG
        printf("%d capture SIGHUP\n", getpid());
#endif
    }
    else {
        printf("%d capture %s\n", getpid(), signo);
    }
    shm_sem_destory(); 
#ifdef DEBUG
    printf("%d exit !\n", getpid());
#endif
    exit(1);
#ifdef FUNC
    printf("==========finish sig_handle_2()==========\n");
#endif
}
int main(int argc, char **argv)
{
    /* 参数检查 */
    if(argc != 2) {
        printf("Usage: %s port      #加端口号启动程序\n", argv[0]);
#ifdef VERSION
        printf("Usage: %s -v        #版本\n", argv[0]);
#endif
        return 0;
    }
#ifdef VERSION
    if(argc == 2 && strcmp("-v", argv[1]) == 0) {
        printf("%s\n", VERSION);
        return 0;
    }
#endif

    /* get_remap_table */
    remap_table = get_remap_table_m("ipmaps");
#if 0
    if(NULL == remap_table) {
        fprintf(stderr, "get_remap_table_m failed\n");
        syslog(LOG_INFO, "[CONFIG] %s启动失败-获取映射表(get_remap_table)", argv[0]); 
        exit(0);
    }
#endif

    /* get_regex_table */
    regex_table = get_regex_table_m("http_devices");

    /* get general_regex */
    ge_re = get_general_regex("general_regex");
#if 0
    if(ge_re == NULL)
    {
        fprintf(stderr, "h_general_regex is NULL\n");
        syslog(LOG_INFO, "[CONFIG] %s启动失败-必填项:通用正则表达式为空(get_general_regex)", argv[0]); 
        exit(0);
    }
    printf("general_regex exists\n");
#endif

    /* get_proxy_config*/

    /* 初始化openssl, ctx_s, ctx_c等 */
    if(ssl_init() < 0) {
        printf("cannot ssl_init()\n");
        return 0;
    }

    /* 建立socket */
    int   l_num = 1024;
    short l_port = 8888;
    char  l_host[] = "0.0.0.0";
    l_fd = create_proxy_server(l_host, l_port, l_num);
    if(l_fd < 0) {
        printf("cannot create proxy server\n");
        return 0;
    }
    /* 监听 */
    switch(fork()) {
        case 0:
            printf("%s在后台启动\n", argv[0]);
            syslog(LOG_INFO, "[CONFIG] %s程序启动", argv[0]); 
            proxy_listen();
            exit(0);
        case -1:
            printf("fork()监听进程失败\n");
            syslog(LOG_INFO, "[CONFIG] %s启动失败-fork failed", argv[0]); 
            err_quit("fork()");
            break;
        default:
            break;
    }
    return 0;
}

int proxy_listen(void)
{
#ifdef FUNC
    printf("==========start proxy_listen(%d)==========\n", getpid());
#endif
    /* 注册信号处理函数 */
    if(signal(SIGPIPE, sig_handle) == SIG_ERR) {
        err_quit("signal()");
    }

    if(signal(SIGINT, sig_handle) == SIG_ERR) {
        err_quit("signal()");
    }
    if(signal(SIGCHLD, sig_handle) == SIG_ERR) {
        err_quit("signal()");
    }

    struct sockaddr_in client_addr;
    bzero(&client_addr, sizeof(client_addr));
    socklen_t len_client = sizeof(client_addr);
    //fd_set rset, wset;
    //int max_fd = 0;
    while(1) {
        /*
        FD_ZERO(&rset);
        FD_ZERO(&wset);
        FD_SET(l_fd, &rset);
        FD_SET(l_fd, &wset);
        max_fd = max_fd>=l_fd?max_fd:l_fd;
        int ret = select(max_fd + 1, &rset, &wset, NULL, NULL);
        if(ret < 0) {
            if(errno == EINTR || errno == EAGAIN) {
                continue;
            }
            perror("select()");         //运行报错:bad file descriptor
            break;
        }
        else if(0 == ret) {
            printf("select timeout\n"); 
            continue;
        }
        else {
            if(FD_ISSET(l_fd, &rset) || FD_ISSET(l_fd, &wset)) {
            */
                c_fd = accept(l_fd, (struct sockaddr *)&client_addr, &len_client);
                if(c_fd < 0) {
                    perror("cannot accept correctly, accept()");
                    continue;
                }

                printf("client online\n");
                switch(fork()) {
                    case -1:
                        close(c_fd);
                        perror("proxy_listen fork()");
                        break;
                    case 0:
                        close(l_fd);
                        handle_client();
                        exit(0);
                    default:
                        close(c_fd);
                        continue;
                }
                /*
            }
        }
        */

    }
    //隐式回收
#ifdef FUNC
    printf("==========finish proxy_listen(%d)==========\n", getpid());
#endif
    return 0;
}
