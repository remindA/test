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
    if(argc != 3) {
        printf("Usage: %s cards num\n", argv[0]);
        return 0;
    }
    int i;
    int people = atoi(argv[1]);
    int num = atoi(argv[2]);
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
    do_magician_card(&head, num); 
    printf("=======================\n");
    print_ring(&head);
    return 0;
}



