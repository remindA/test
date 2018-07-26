/*
 * =====================================================================================
 *
 *       Filename:  main.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年07月26日 15时01分34秒
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
#include <string.h>
#include <errno.h>

int main(void)
{
start:
    switch(fork()) {
    case 0:
        break;
    case -1:
        perror("fork()");
        exit(0);
    default:
        if(waitpid(-1, NULL, 0) > 0) {
            goto start;
        }
        exit(0);
    }
    while(1) {
        printf("pid = %d\n", getpid());
        sleep(1);
    }
    return 0;
}

