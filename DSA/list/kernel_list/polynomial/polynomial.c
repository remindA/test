/*
 * =====================================================================================
 *
 *       Filename:  polynomial.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年04月12日 14时37分24秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#include "polynomial.h"

/*
 * 多项式相加
 * polynomial_add()
 * @pnsum: 结果-已排序
 * @pna: 多项式-未排序
 * @pnb: 多项式-未排序
 */

int polynomial_add(struct list_head *pnsum,
                   struct list_head *pna,
                   struct list_head *pnb)
{
    /* 检查参数 */
    INIT_LIST_HEAD(pnsum);
    int ret1 = polynomial_sort_copy(pnsum, pna);
    polynomial_print(pnsum);
    int ret2 = polynomial_sort_copy(pnsum, pnb);
    polynomial_print(pnsum);
    return ret1 && ret2;
    //return polynomial_sort_copy(pnsum, pna) && \ 
           //polynomial_sort_copy(pnsum, pnb);
}


int polynomial_sort_copy(struct list_head *head_dst, struct list_head *head_src) 
{
    struct list_head *s;;
    list_for_each(s, head_src) {
        term_t *src = list_entry(s, term_t, list);
        printf("src->exp = %d\n", src->exp);
        struct list_head *d;
        
        if(list_empty(head_dst)) {
            term_t *term = (term_t *)calloc(1, sizeof(term_t));
            term->coe = src->coe;
            term->exp = src->exp;
            list_add_tail(&(term->list), head_dst);
            continue;
        }

        list_for_each(d, head_dst) {
            term_t *dst = list_entry(d, term_t, list);
            printf("dst->exp = %d\n", dst->exp);
            if(src->exp < dst->exp) {
                if((dst->list).next != head_dst) {
                    continue;
                }
                else {
                    term_t *term = (term_t *)calloc(1, sizeof(term_t));
                    if(NULL == term) {
                        perror("calloc in polynomial_sort_copy");
                        return -1;
                    }
                    term->exp = src->exp;
                    term->coe = src->coe;
                    list_add_append(&(term->list), d);
                    break;
                }
            }
            else if(src->exp == dst->exp) {
                if(0 == src->coe + dst->coe) {
                    list_del(&(dst->list));
                }
                else {
                    dst->coe += src->coe;
                }
                break;
            }
            else {
                term_t *term = (term_t *)calloc(1, sizeof(term_t));
                if(NULL == term) {
                    perror("calloc in polynomial_sort_copy");
                    return -1;
                }
                term->exp = src->exp;
                term->coe = src->coe;
                list_add_insert(&(term->list), d);
                break;
            }
        }
    }
    return 1;
}

void polynomial_print(struct list_head *head)
{
    struct list_head *pos;
    printf("\n");
    list_for_each(pos, head) {
        term_t *term = list_entry(pos, term_t, list);
        printf("%dx^%d + ", term->coe, term->exp);
    }
    printf("\n");
}
