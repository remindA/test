/*
 * =====================================================================================
 *
 *       Filename:  polynomial.h
 *
 *    Description:  多项式，定义结构体，四则运算函数等
 *
 *        Version:  1.0
 *        Created:  2018年04月12日 00时25分20秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#ifndef _POLYNOMIAL_H_
#define _POLYNOMIAL_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "mylist.h"
/*
 * 每一相包含
 *      指数: 整数
 *      系数: 不为0
 *  多项式 -- polynomial 
    系　数 -- coefficient  --> coe
    指　数 -- exponent     --> exp

 */
#define POLYNOMIAL_ADD   1
#define POLYNOMIAL_MINUS 2
#define POLYNOMIAL_MUL   3
typedef int coe_t;
typedef int exp_t;
typedef struct {
    coe_t coe;
    exp_t exp;
    struct list_head list;
}term_t;


int polynomial_add(struct list_head *pnsum, struct list_head *pna, struct list_head *pnb);
int polynomial_mul(struct list_head *pnsum, struct list_head *pna, struct list_head *pnb); 
int polynomial_minus(struct list_head *pnsum, struct list_head *pna, struct list_head *pnb); 
int polynomial_sort_insert(struct list_head *head_dst, struct list_head *head_src, int opt); 
int polynomial_term_sort_insert(struct list_head *head, coe_t coe, exp_t exp);
void polynomial_print(struct list_head *head);

#endif

