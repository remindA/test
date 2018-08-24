/*
 * =====================================================================================
 *
 *       Filename:  file_line_func.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年08月20日 20时54分17秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  NYB (), niuyabeng@126.com
 *   Organization:  
 *
 * =====================================================================================
 */

#include <stdio.h>

int main(int argc, char **argv)
{
    printf("we are in file: %s, line: %d, function: %s\n", __FILE__, __LINE__, __func__);
    return 0;
}
