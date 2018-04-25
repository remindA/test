/*
 * =====================================================================================
 *
 *       Filename:  var_list.c
 *
 *    Description:  测试可变参数
 *
 *        Version:  1.0
 *        Created:  2018年01月08日 10时51分04秒
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
#include <stdarg.h>
#include <sys/types.h>


void test(char *fmt, ...)
{
    va_list ap;
    int len;
    int offset = 0;
    int len_tot = 0;
    char *buff;
    char *fmt_tmp = fmt;
    char str[100] = {0};
    va_start(ap, fmt);
    while(*fmt) {
        switch(*fmt++) {
            case 'l':
                len = va_arg(ap, int);
                printf("len = %d\n", len);
                len_tot += len;
                break;
            case 's':
                buff = va_arg(ap, char *);
            default:
                break;
        }
    }
    if(len_tot > 100) {
        printf("len_tot =%d > %d\n", len_tot, 100);
        return;
    }
    va_end(ap);

    fmt = fmt_tmp;
    va_start(ap, fmt);
    while(*fmt) {
        switch(*fmt++) {
            case 'l':
                len = va_arg(ap, int);
                break;
            case 's':
                buff = va_arg(ap, char *);
                printf("offset = %d\n", offset);
                memcpy(str + offset, buff, len);
                offset += len;
                break;
            default:
                break;
        }
    }
    va_end(ap);
    int i;
    for(i = 0; i < len_tot; i++)
        printf("%c", *(str + i));
}

int main(int argc, char **argv)
{
    test("lslsls", strlen("hello "), "hello", strlen("-->"), "-->", strlen("world"), "world");
    return 0;
}

