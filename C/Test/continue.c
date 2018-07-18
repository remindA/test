/*
 * =====================================================================================
 *
 *       Filename:  continue.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年07月04日 12时29分26秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <unistd.h>

int main()
{
    int i = 0;
    while(1){
        sleep(1);
        i++;
        if(i %2 == 0) {
            if(i % 3 == 0) {
                printf("bingo\n");
                continue;
            }
            else {
                printf("%d\n", i);
            }
        }
        else {
            printf("%d\n", i);
        }
    }
    return 0;
}
