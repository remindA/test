/*
 * =====================================================================================
 *
 *       Filename:  array_enum.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年08月21日 00时34分14秒
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


enum {
    ST1,
    ST2,
    ST3,
    ST_MAX
};

const char str[ST_MAX][32] = {
    [ST1] = "ST1",
    [ST2] = "ST2",
    [ST3] = "ST3"
};

int main(int argc, char **argv)
{
    int i = 0;
    for(i = 0; i < ST_MAX; i++) {
        printf("%s\n", str[i]);
    }
    return 0;
}


