/*
 * =====================================================================================
 *
 *       Filename:  getopt_test.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年01月29日 13时21分17秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    int opt;
    int proxy = 0;
    while((opt = getopt(argc, argv, "s")) != -1) {
        switch(opt) {
            case 's':
                proxy = 1;
                break;
            default:
                printf("no such aption\n");
                break;
        }
    }
    printf("proxy = %d\n", proxy);
    return 0;
}
