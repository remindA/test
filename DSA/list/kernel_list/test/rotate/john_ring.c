/*
 * =====================================================================================
 *
 *       Filename:  john_ring.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年04月16日 23时57分24秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#include "john_ring.h"

int do_john_ring(struct list_head *head, int step, int left)
{
    if(list_empty(head)) {
        return -1;
    }
    if(left == list_count(head)) {
        return 0;
    }
    int i;
    struct list_head *end;
    struct list_head *start = head->next;
    print_ring(head);
    while(1) {
        end = start;
        for(i = 0; i < step; i++) {
            end = end->next;
            end = end==head?end->next:end;
        }
        start = end->next;
        start = start==head?start->next:start;
        john_t *john = list_entry(end, john_t, list);
        list_del(end);
        free(john);
        if(list_count(head) != left) {
            print_ring(head);
        }
        else {
            break;
        }
    }
}


void print_ring(struct list_head *head)
{
    struct list_head *pos;
    list_for_each(pos, head) {
        john_t *john = list_entry(pos, john_t, list);
        printf("%d-->", john->number);
    }
    printf("\n");
}


struct list_head *do_john_ring2(struct list_head *head, int step, int left)
{
    if(list_empty2(head) || left == list_count2(head)) {
        return head;
    }
    int i;
    struct list_head *end;
    struct list_head *start = head;
    print_ring2(start);
    while(1) {
        end = start;
        for(i = 0; i < step; i++) {
            end = end->next;
        }
        start = end->next;
        john_t *john = list_entry(end, john_t, list);
        list_del(end);
        free(john);
        if(list_count2(start) != left) {
            print_ring2(start);
        }
        else {
            break;
        }
    }
    return start;
}


void print_ring2(struct list_head *head)
{
    struct list_head *pos = head;
    while(pos->next != head) {
        john_t *john = list_entry(pos, john_t, list);
        printf("%d-->", john->number);
        pos = pos->next;
    }
    john_t *john = list_entry(pos, john_t, list);
    printf("%d-->", john->number);
    printf("\n");
}

void do_rotate(struct list_head *head, int dir, int step)
{
    list_rotate(head, dir, step);
}
