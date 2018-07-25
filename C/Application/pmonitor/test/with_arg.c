/*
 * =====================================================================================
 *
 *       Filename:  with_arg.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年07月23日 09时53分18秒
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
        printf("with arg\n");
        int i;
        for(i = 0; i < argc; i++) {
            printf("%s ", argv[i]);
        }
        printf("\n");
    }
    return 0;
}



