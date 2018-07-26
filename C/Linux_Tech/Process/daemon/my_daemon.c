/*
 * =====================================================================================
 *
 *       Filename:  my_daemon.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年07月26日 14时27分45秒
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

int main(int argc, char **argv)
{
    pid_t pid = fork();
    switch(pid) {
    case 0:
        daemon(0, 0);
        while(1) {
            sleep(1);
            printf("This message should not show up\n");
        }
        exit(0);
    case -1:
        perror("fork()");
        break;
    default:
        break;
    }
    return 0;
}

