/*
 * =====================================================================================
 *
 *       Filename:  main.c
 *
 *    Description:  测试栈程序
 *
 *        Version:  1.0
 *        Created:  2018年05月06日 22时54分55秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#include "stack.h"

int main(int argc, char *argv)
{
    stack_t *stack = stack_create();
    stack_init(stack, 10);
    int i;
    for(i = 0; i < stack->size; i++){
        stack_push(stack, i);
    }
    node_t *node;
    stack_for_each(node, stack){
        printf("%d\t", node->data);
    }
    printf("\n==========================================\n");
    for(i = 0; i< stack->size; i++){
        int data;
        stack_pop(stack, &data);
        printf("%d\t", data);
    }
    stack_for_each(node, stack){
        printf("%d\t", node->data);
    }
    printf("\n==========================================\n");

    return 0;
}

