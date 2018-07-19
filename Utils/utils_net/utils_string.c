/*
 * =====================================================================================
 *
 *       Filename:  utils_string.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年07月19日 20时43分55秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */


int is_empty_line(const char *line, int len)
{
    if(NULL == line) {
        return 0;
    }

    if(len > 2 || len == 0) {
        return 0;
    }
    else {
        return len==1?(line[0]=='\n'):((line[0]=='\r')&&(line[1]=='\n'));
    }
}
