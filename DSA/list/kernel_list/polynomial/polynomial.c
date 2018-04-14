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

int polynomial_add(struct list_head *pnsum, struct list_head *pna, struct list_head *pnb)
{
    INIT_LIST_HEAD(pnsum);
    int ret1 = polynomial_sort_insert(pnsum, pna, POLYNOMIAL_ADD);
    int ret2 = polynomial_sort_insert(pnsum, pnb, POLYNOMIAL_ADD);
    return ret1 && ret2;
}

int polynomial_minus(struct list_head *pnsum, struct list_head *pna, struct list_head *pnb)
{
    printf("=== in minus ==\n");
    INIT_LIST_HEAD(pnsum);
    int ret1 = polynomial_sort_insert(pnsum, pna, POLYNOMIAL_ADD);
    int ret2 = polynomial_sort_insert(pnsum, pnb, POLYNOMIAL_MINUS);
    printf("=== out minus ==\n");
    return ret1 && ret2;
}

int polynomial_mul(struct list_head *pnsum, struct list_head *pna, struct list_head *pnb) 
{
    struct list_head *pos_a;
    list_for_each(pos_a, pna) {
        struct list_head *pos_b;
        list_for_each(pos_b, pnb) {
            term_t *term_a = list_entry(pos_a, term_t, list);
            term_t *term_b = list_entry(pos_b, term_t, list);
            printf("%d*%d %d+%d\n", term_a->coe, term_b->coe, term_a->exp, term_b->exp);
            polynomial_term_sort_insert(pnsum, term_a->coe * term_b->coe, term_a->exp + term_b->exp);
        }
    }
}


/*
 * @polynomial_term_sort_insert: 多项式插入新节点
 * @head: 要插入的多项式链表的头指针
 * @coe: 新项系数
 * @exp: 新项指数
 */
int polynomial_term_sort_insert(struct list_head *head, coe_t coe, exp_t exp)
{
    printf("=== in term insert ===\n");
    int type = -1;
    if(list_empty(head)) {
        term_t *new = (term_t *)calloc(1, sizeof(term_t));
        if(NULL == new) {
            perror("calloc in polynomial_term_sort_insert");
            return -1;
        }
        new->coe = coe;
        new->exp = exp;
        list_add_tail(&(new->list), head);
        type = 1;
        goto end;
    }

    struct list_head *pos;
    list_for_each(pos, head) {
        term_t *dst = list_entry(pos, term_t, list);
        if(exp < dst->exp) {
            if(pos->next == head) {
                term_t *new = (term_t *)calloc(1, sizeof(term_t));
                if(NULL == new) {
                    perror("calloc in polynomial_term_sort_insert");
                    return -1;
                }
                new->coe = coe;
                new->exp = exp;
                list_add_append(&(new->list), pos);
                type = 1;
                goto end;
            }
        }
        else if(exp > dst->exp) {
            term_t *new = (term_t *)calloc(1, sizeof(term_t));
            if(NULL == new) {
                perror("calloc in polynomial_term_sort_insert");
                return -1;
            }
            new->coe = coe;
            new->exp = exp;
            list_add_insert(&(new->list), pos);
            type = 1;
            goto end;
        }
        else {
            if(0 == coe + dst->coe) {
                list_del(pos);
                free(dst);
            }
            else {
                dst->coe += coe;
            }
            type = 0;
            goto end;
        }
    }
    printf("=== in term insert ===\n");
end: 
    return type;
}


int polynomial_sort_insert(struct list_head *head_dst, struct list_head *head_src, int opt) 
{
    printf("opt = %d\n", opt);
    struct list_head *s;;
    list_for_each(s, head_src) {
        term_t *src = list_entry(s, term_t, list);
        printf("src->coe = %d, src->exp = %d\n", opt==POLYNOMIAL_ADD?src->coe:0-src->coe, src->exp);
        if(polynomial_term_sort_insert(head_dst, opt==POLYNOMIAL_ADD?src->coe:0-src->coe, src->exp) < 0) {
            return -1;
        }
    }
    return 1;
}

void polynomial_print(struct list_head *head)
{
    struct list_head *pos;
    if(list_empty(head)) {
        printf("0");
    }
    list_for_each(pos, head) {
        term_t *term = list_entry(pos, term_t, list);
        printf("%dx^%d + ", term->coe, term->exp);
    }
    printf("\n\n");
}
