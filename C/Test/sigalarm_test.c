/*
 * =====================================================================================
 *
 *       Filename:  sigalarm_test.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年07月20日 15时17分08秒
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
#include <string.h>
#include <unistd.h>
#include <signal.h>

typedef void *(sighandle_t)(int);

void alrm_handle(int signo)
{
    printf("alarm once");
}

int main(int argc, char **argv)
{

    if(signal(SIGALRM, alrm_handle) == SIG_ERR) {
        perror("signal()");
        return -1;
    }
    alarm(2);
    while(1) ;
    return 0;
}



