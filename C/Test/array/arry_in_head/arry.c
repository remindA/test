/*
 * =====================================================================================
 *
 *       Filename:  arry.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年03月31日 13时28分14秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#include "arry.h"

int arry[] = {
    1, 2, 3, 4, 5
};

int main()
{
    int len = sizeof(arry)/sizeof(int);
    int i = 0;
    for(i = 0; i < len; i++) {
        printf("%d\n", arry[i]);
    }
    return 0;
}
