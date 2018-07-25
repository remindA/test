/*
 * =====================================================================================
 *
 *       Filename:  main.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年07月21日 14时23分11秒
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

void free_argv(char **argv)
{
    char **tmp; 
    for(tmp = argv; *tmp; tmp++) {
        printf("free %s\n", *tmp);
        free(*tmp);
        *tmp = NULL;
    }
}

int main()
{
    int _argc = 0;
    char **_argv = NULL;
    const char *buff = "pmonitor   http_worker   10.10.10.231   5060  192.168.1.10  5060";
    char *c;
    char *start = NULL;
    char *end = NULL;
    for(c = strchr(buff, ' '); *c != '\0'; c++) {
        if(isspace(*c) && (*(c+1) != '\0' && !isspace(*(c+1)))) {
            start = c+1;
            printf("start = [%s]\n", start);
        }
        if(!isspace(*c) && (*(c+1) == '\0' || (*(c+1) != '\0' && isspace(*(c+1))))){
            end = c;
            printf("end = [%s]\n", end);
        }
        if(start && end && end > start) {
            _argc++;
            printf("_argc = %d\n", _argc);
            _argv = (char **)realloc(_argv, (_argc+1)*sizeof(char *));
            if(NULL == _argv) {
                perror("realloc");
            }
            printf("1\n");

            _argv[_argc] = NULL;
            _argv[_argc-1] = (char *)calloc(1, 1+end-start+1);
            if(NULL == _argv[_argc-1]) {
                perror("calloc()");
                exit(0);
            }
            printf("2\n");
            strncpy(_argv[_argc-1], start, 1+end-start);
            printf("3\n");
            int i;
            for(i = 0; i <= _argc; i++) {
                printf("%d --> %s\n", i, _argv[i]);
            }
            start = end = NULL;
        }
    }
    free_argv(_argv);
    int i;
    for(i = 0; i <= _argc; i++) {
        printf("%d --> %s\n", i, _argv[i]);
    }

    return 0;
}



