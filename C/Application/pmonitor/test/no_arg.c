/*
 * =====================================================================================
 *
 *       Filename:  no_arg.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年07月23日 09时51分39秒
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
    while(1) {
        sleep(2);
        printf("no arg\n");
    }
    return 0;
}

