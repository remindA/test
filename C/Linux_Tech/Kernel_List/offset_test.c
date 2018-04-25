#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "list.h"


#pragma pack(1)
struct a
{
    int num;
    char c;
    double d;
    struct a *s;
};


struct list_head
{
    struct list_head *prev;
    struct list_head *next;
};

struct info_list
{
    int  age;
    int  gender;
    char name[32];
    struct list_head node;
};

struct info_list2
{
    int  age;
    int  gender;
    char name[32];
    struct list_head *node;
};
void init_list_head(struct list_head *list);
int main()
{
    printf("sizeof(info_list) =%d\n", sizeof(struct info_list));
    printf("sizeof(info_list2)=%d\n", sizeof(struct info_list2));
    printf("offsetof(struct a, num)=%d\n", offsetof(struct a, num));
    printf("offsetof(struct a, c)=%d\n", offsetof(struct a, c));
    printf("offsetof(struct a, d)=%d\n", offsetof(struct a, d));
    printf("offsetof(struct a, s)=%d\n", offsetof(struct a, s));

    struct info_list new;
    //init_list_head(new.node);
    printf("new_ptr     =%p\n", &new);
    printf("new.node_ptr=%p\n", &(new.node));
    printf("========before init_list_head=====\n");
    printf("new.node.prev=%p\n", new.node.prev);
    printf("new.node.next=%p\n", new.node.next);
    printf("========after init_list_head=====\n");
    init_list_head(&(new.node));
    printf("new.node.prev=%p\n", new.node.prev);
    printf("new.node.next=%p\n", new.node.next);
    return 0;
}

/* insert a node
    struct info_list new;
    __add_to_head(new.node, head);
    __add_to_tail(new.node, tail);
    __add_to_pos(new.node, prev, next);
*/
void init_list_head(struct list_head *list)
{
    list->next = list;
    list->prev = list;
}

/*
void list_add_to_head(struct list_head *node, struct list_head *head)
{
    __list_add(node, head->prev, head);
}

void list_add_to_tail(struct list_head *node, struct list_head *tail)
{
    __list_add(node, tail, tail->next);
}

void __list_add(struct list_head *node, struct list_head *prev, struct list_head *next)
{
    prev->next = node;
    node->next = next;
    next->prev = next;
    node->prev = prev;
}

*/

