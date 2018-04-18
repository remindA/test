/*
 * =====================================================================================
 *
 *       Filename:  main.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年04月17日 00时23分10秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#include "john_ring.h"

int main(int argc, char **argv)
{
    if(argc != 4) {
        printf("Usage: %s people step left\n", argv[0]);
        return 0;
    }
    int i;
    int people = atoi(argv[1]);
    int step = atoi(argv[2]);
    int left  = atoi(argv[3]);
    if(people < 2) {
        printf("people must >= 2\n");
        return 0;
    }
    if(left > people) {
        printf("people must > left, %d > %d\n", people, left);
        return 0;
    }
    john_t *head = (john_t *)calloc(1, sizeof(john_t));
    init_list_head(&(head->list));
    head->number = 1;
    for(i = 2; i <= people; i++) {
        john_t *john = (john_t *)calloc(1, sizeof(john_t));
        if(john == NULL) {
            perror("calloc in main");
            return -1;
        }
        john->number = i;
        list_add_tail(&(john->list), &(head->list));
    }
    struct list_head *alive = do_john_ring2(&(head->list), step, left);
    printf("=======================\n");
    print_ring2(alive);
    return 0;
}



