/*
 * =====================================================================================
 *
 *       Filename:  test.c
 *
 *    Description:  测试Posix有名信号量的使用
 *
 *        Version:  1.0
 *        Created:  2018年01月05日 16时01分55秒
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
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <semaphore.h>

int main(int argc, char **argc)
{
    
    switch(fork()) {
        case -1:
            printf("cannot fork child");
            return 0;
        case 0:
        default:
            break;
    }
}

