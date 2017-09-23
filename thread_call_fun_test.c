/* Date     : 2017.08.04
 * Author   : NYB
 * Intro    : 多线程，每个线程都调用函数A，函数A中访问全局变量，加锁访问。
 * Result   : global从0自增到MAX_COUNT
 */
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>

#define MAX_COUNT   5000000
#define SLEEP_TIME  (1)


void err_quit(const char *api);
void thread_fun(void *arg);
void cnt_plus_one();

int global = 0;
pthread_mutex_t mutex;

int main()
{
    if(pthread_mutex_init(&mutex, NULL) < 0)
        err_quit("pthread_mutex_init");
    
    int i = 0;
    for(i = 0; i < 3; i++)
    {
        pthread_t th;
        if(pthread_create(&th, NULL, (void *)thread_fun, NULL) != 0)
            err_quit("pthread_create");
    }

    while(1)
    {
        pthread_mutex_lock(&mutex);
        if(global > MAX_COUNT)
            break;  
        pthread_mutex_unlock(&mutex);
    }
    pthread_mutex_destroy(&mutex);
    return 0;
}

void err_quit(const char *api)
{
    perror(api);
    exit(1);
}
void thread_fun(void *arg)
{
    int retval;
    pthread_t tid = pthread_self();
    pthread_detach(tid);

    while(1)
    {
        //printf("tid->%ld  ", tid);
        cnt_plus_one();
        //usleep(SLEEP_TIME);

    }
    printf("tid->%ld exit\n", tid);
    pthread_exit(&retval);
}

void cnt_plus_one()
{
    pthread_mutex_lock(&mutex);
    global++;
    printf("global=%d\n", global);
    pthread_mutex_unlock(&mutex);
}
