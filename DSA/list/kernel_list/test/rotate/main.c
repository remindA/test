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
        printf("Usage: %s people dir(0,1) step.\n", argv[0]);
        return 0;
    }
    int i;
    int people = atoi(argv[1]);
    int dir = atoi(argv[2]);
    int step  = atoi(argv[3]);
    if(people < 2) {
        printf("people must >= 2\n");
        return 0;
    }
    struct list_head head;
    init_list_head(&head);
    for(i = 1; i <= people; i++) {
        john_t *john = (john_t *)calloc(1, sizeof(john_t));
        if(john == NULL) {
            perror("calloc in main");
            return -1;
        }
        john->number = i;
        list_add_tail(&(john->list), &head);
    }
    //do_john_ring(&head, step, left);
    do_rotate(&head, dir, step);
    printf("=======================\n");
    print_ring(&head);
    return 0;
}



