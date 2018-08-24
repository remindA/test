/*
 * =====================================================================================
 *
 *       Filename:  select_timer.c
 *
 *    Description:  使用select实现一个定时器事件
 *
 *        Version:  1.0
 *        Created:  08/19/2018 08:11:20 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  NYB (), niuyabeng@126.com
 *   Organization:  
 *
 * =====================================================================================
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/select.h>
#include <errno.h>


void timer_event(int times, int sec, int usec)
{
    struct timeval tout;
    tout.tv_sec = sec;
    tout.tv_usec = usec;
    int num = 0;
    while(times > 0) {
        times--;
        num++;
        tout.tv_sec = sec;
        tout.tv_usec = usec;
        int ret = select(0, NULL, NULL, NULL, &tout);
        switch(ret) {
        case 0:
            printf("%d, %ld\n", num, time(NULL));
            break;
        case -1:
            perror("select()");
            break;
        default:
            break;
        }
    }
}

int main(int argc, char **argv)
{
    timer_event(10, 1, 0);
    return 0;
}
