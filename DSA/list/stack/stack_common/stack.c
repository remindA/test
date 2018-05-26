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

/*
 * return:
 *  ok   : stack
 *  fail : NULL 
 */
stack_t *stack_create()
{
    stack_t * stack = (stack_t *)calloc(1, sizeof(stack_t));
    if(NULL == stack) {
        perror("calloc");
        return NULL;
    }
    return stack;
}

/*
 * type_len : 数据类型的长度
 * size     : 栈的大小
 * return:
 *  ok  : 0
 *  fail: -1
 */
int stack_init(stack_t *stack, int type_len, int size)
{
    void *array = calloc(size, type_len);
    if(NULL == array) {
        perror("calloc");
        return -1;
    }
    stack->bot = array;
    stack->top = NULL;
    stack->size = size;
    stack->type_len = type_len;
    return 0;
}

/*
 * 判断栈空
 */
int stack_is_empty(stack_t *stack)
{
    return NULL==stack->top;
}

/*
 * 判断栈满
 */
int stack_is_full(stack_t *stack)
{
    return stack->top-stack->bot==stack->type_len*(stack->size-1);
}

/*
 * 判断栈中是否只有一个元素
 */
int stack_is_single(stack_t *stack)
{
    return stack->top==stack->bot;
}

/*
 * return:
 *  ok  : 0
 *  fail: -1
 */
int stack_push(stack_t *stack, void *data, int type_len)
{
    if(type_len != stack->type_len) {
        fprintf(stderr, "stack_push: incompetiable data type and stack type\n");
        return -1;
    }
    if(stack_is_full(stack)) {
        return -1;
    }
    else if(stack_is_empty(stack)) {
        stack->top = stack->bot;
    }
    else {
        stack->top += type_len;
    }
    memcpy(stack->top, data, stack->type_len); 
    return 0;
}


/*
 * return:
 *  ok  : 0
 *  fail: -1
 */
int stack_pop(stack_t *stack, void *data, int type_len)
{
    if(type_len != stack->type_len) {
        fprintf(stderr, "stack_pop: incompetiable data type and stack type\n");
        return -1;
    }
    if(stack_is_empty(stack)) {
        return -1;
    }
    memcpy(data, stack->top, stack->type_len);
    if(stack_is_single(stack)) {
        stack->top = NULL;
    }
    else {
        stack->top -= stack->type_len;
    }
    return 0;
}

/*
 * 清空栈(栈顶置空)
 */
int stack_clear(stack_t *stack)
{
    stack->top = NULL;
}




