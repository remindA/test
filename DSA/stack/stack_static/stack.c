/*
 * =====================================================================================
 *
 *       Filename:  stack.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年05月06日 22时02分11秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#include "stack.h"

stack_t *stack_create()
{
    stack_t * stack = (stack_t *)calloc(1, sizeof(stack_t));
    if(NULL == stack) {
        perror("calloc");
        return NULL;
    }
    return stack;
}

int stack_init(stack_t *stack, int size)
{
    node_t *array = (node_t *)calloc(size, sizeof(node_t));
    if(NULL == array) {
        perror("calloc");
        return -1;
    }
    stack->bot = array;
    stack->top = NULL;
    stack->size = size;
    return 0;
}

int stack_is_empty(stack_t *stack)
{
    return NULL==stack->top;
}

int stack_is_full(stack_t *stack)
{
    return stack->top-stack->bot==sizeof(node_t)*(stack->size-1);
}

int stack_is_single(stack_t *stack)
{
    return stack->top==stack->bot;
}

int stack_push(stack_t *stack, int data)
{
    if(stack_is_full(stack)) {
        return -1;
    }
    else if(stack_is_empty(stack)) {
        stack->top = stack->bot;
    }
    else {
        stack->top++; //+1还是+sizeof(node_t);
    }
    stack->top->data = data; 
    return 0;
}


/* 注意:指针加法和减法 */
int stack_pop(stack_t *stack, int *data)
{
    if(stack_is_empty(stack)) {
        return -1;
    }
    *data = stack->top->data;
    if(stack_is_single(stack)) {
        stack->top = NULL;
    }
    else {
        stack->top--;
    }
    return 0;
}


int stack_clear(stack_t *stack)
{
    stack->top = NULL;
}




