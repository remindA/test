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
typedef struct {
    int exp;
    int coe;
    struct list_head list;
}term_t;


int polynomial_add(struct list_head *pnsum,
                   struct list_head *pna,
                   struct list_head *pnb);
int polynomial_sort_copy(struct list_head *head_dst, struct list_head *head_src);
void polynomial_print(struct list_head *head);

#endif

