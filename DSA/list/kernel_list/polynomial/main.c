/*
 * =====================================================================================
 *
 *       Filename:  main.c
 *
 *    Description:  测试多项式相加
 *
 *        Version:  1.0
 *        Created:  2018年04月12日 16时32分09秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#include "polynomial.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    if(argc < 2) {
        printf("%s file\n", argv[0]);
        return 0;
    }
    char line[128];
    FILE *fp = fopen(argv[1], "r");
    if(NULL == fp) {
        perror("fopen");
        return -1;
    }

    int count = 0;
    struct list_head poly_a, poly_b, poly_sum;
    INIT_LIST_HEAD(&poly_a);
    INIT_LIST_HEAD(&poly_b);
    INIT_LIST_HEAD(&poly_sum);

    while(!feof(fp)) {
        count++;
        if(count > 2) {
            break;
        }
        memset(line, 0, sizeof(line));
        fgets(line, 128, fp);
        char *p;
        char *left = line;
        printf("%s\n", line);
        while((p = strstr(left, "+"))) {
            *p = '\0';
            printf("[%s] ", left);
            char coe[32];
            char exp[32];
            if(2 != sscanf(left, "%[^x]x%s", coe, exp)) {
                printf("cannot get coe and exp from '%s'\n", left);
                continue;
            }
            term_t *term = (term_t *)calloc(1, sizeof(term_t));
            if(NULL == term) {
                perror("calloc");
                //free_polynomial(&poly_a);
                return -1;
            }
            term->coe = atoi(coe);
            term->exp = atoi(exp);
            if(count == 1) {
                list_add_tail(&(term->list), &poly_a);
            }
            else if(count == 2) {
                list_add_tail(&(term->list), &poly_b);
            }
            left = p + 1;
        }
        printf("[%s]", left);
        char coe[32];
        char exp[32];
        if(2 != sscanf(left, "%[^x]x%s", coe, exp)) {
            printf("cannot get coe and exp from '%s'\n", left);
        }
        term_t *term = (term_t *)calloc(1, sizeof(term_t));
        if(NULL == term) {
            perror("calloc");
            //free_polynomial(&poly_a);
            return -1;
        }
        term->coe = atoi(coe);
        term->exp = atoi(exp);
        if(count == 1) {
            list_add_tail(&(term->list), &poly_a);
        }
        else if(count == 2) {
            list_add_tail(&(term->list), &poly_b);
        }
    }
    fclose(fp);
    polynomial_print(&poly_a);
    polynomial_print(&poly_b);
    polynomial_add(&poly_sum, &poly_a, &poly_b);
    return 0;
}
