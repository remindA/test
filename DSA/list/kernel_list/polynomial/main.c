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
    struct list_head poly_a;
    struct list_head poly_b;
    struct list_head poly_sum;
    struct list_head poly_mul;
    struct list_head poly_minus;
    INIT_LIST_HEAD(&poly_a);
    INIT_LIST_HEAD(&poly_b);
    INIT_LIST_HEAD(&poly_sum);
    INIT_LIST_HEAD(&poly_mul);
    INIT_LIST_HEAD(&poly_minus);

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
            if(count == 1) {
                polynomial_term_sort_insert(&poly_a, atoi(coe), atoi(exp));
            }
            else if(count == 2) {
                polynomial_term_sort_insert(&poly_b, atoi(coe), atoi(exp));
            }
            left = p + 1;
        }
        printf("[%s]", left);
        char coe[32];
        char exp[32];
        if(2 != sscanf(left, "%[^x]x%s", coe, exp)) {
            printf("cannot get coe and exp from '%s'\n", left);
        }
        if(count == 1) {
            polynomial_term_sort_insert(&poly_a, atoi(coe), atoi(exp));
        }
        else if(count == 2) {
            polynomial_term_sort_insert(&poly_b, atoi(coe), atoi(exp));
        }
    }
    fclose(fp);
    polynomial_add(&poly_sum, &poly_a, &poly_b);
    polynomial_mul(&poly_mul, &poly_a, &poly_b);
    polynomial_minus(&poly_minus, &poly_a, &poly_b);
    printf("a is :\n\t");
    polynomial_print(&poly_a);
    printf("b is :\n\t");
    polynomial_print(&poly_b);
    printf("sum is :\n\t");
    polynomial_print(&poly_sum);
    printf("mul is :\n\t");
    polynomial_print(&poly_mul);
    printf("minus is :\n\t");
    polynomial_print(&poly_minus);
    return 0;
}
