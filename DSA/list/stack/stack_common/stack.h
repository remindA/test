/*
 * =====================================================================================
 *
 *       Filename:  stack.h
 *
 *    Description:  数组做静态栈，栈会满,栈大小可配置
 *                  栈不允许动态扩容
 *
 *        Version:  1.0
 *        Created:  2018年05月04日 16时58分29秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#ifndef _STACK_STATIC_H_
#define _STACK_STATIC_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


typedef struct {
    int  size;
    int  type_len;
    void *bot;
    void *top;
}stack_t;

#define stack_for_each(pos, stack) \
    for(pos = stack->bot; pos <= stack->top; pos += stack->type_len)

stack_t *stack_create();
int stack_init(stack_t *stack, int type_len, int size);
int stack_is_empty(stack_t *stack);
int stack_is_full(stack_t *stack);
int stack_is_single(stack_t *stack);
int stack_push(stack_t *stack, void *data, int type_len);
int stack_pop(stack_t *stack, void *data, int type_len);
int stack_clear(stack_t *stack);

#endif

