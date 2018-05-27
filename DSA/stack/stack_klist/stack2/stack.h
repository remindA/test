/*
 * =====================================================================================
 *
 *       Filename:  stack.h
 *
 *    Description:  内核链表实现栈
 *
 *        Version:  1.0
 *        Created:  2018年05月04日 16时34分59秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#include "mylist.h"

typedef struct{
    int data;
    struct list_head list;
}node_t;

typedef struct{
    struct list_head *bot;
    struct list_head *top;
}stack_t;

stack_t stack_create()
{
    stack_t *stack = (stack_t *)calloc(1, sizeof(stack_t));
    struct list_head *head = (struct list_head *)calloc(1, sizeof(struct list_head));
    init_list_head(head);
    stack->bot = head;
    stack->top = head;
    return stack;
}

int stack_push(stack_t *stack, int data)
{
    node_t *top = (node_t *)calloc(1, sizeof(node_t));
    top->data = data;
    list_add_append(stack->top, &(top->list));
    stack->top = top;
    return 0;
}

int stack_pop(stack_t *stack, int *data)
{
    struct list_head *top = stack->top;
    node_t *del = list_entry(top, node_t, list);
    *data = del->data;
    stack->top = top->prev;
    list_del(top);
    free(del);
    return 0;
}

int stack_is_empty(stack_t *stack)
{
    return stack->bot == stack->top?0:1;
}

int stack_clear(stack_t *stack)
{
    /* 只要栈不为空就pop */
    int data;
    while(stack->bot != stack->top) {
        stack_pop(stack, &data);
    }
    return 0;
}

int stack_traversal(stack_t *stack)
{
    /* 双向循环链表可以从两个方向遍历 */
    struct list_head *pos;
    list_for_each(pos, stack->bot) {
        //do_stuff;
    }
    return 0;
}



