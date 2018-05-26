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

typedef struct{
    char    name[20];
    int     id;
    int     age;
    int     salary;
}employ_t;


void employ_init(employ_t *e, const char *name, int id, int age, int salary)
{
    strcpy(e->name, name);
    e->id = id;
    e->age = age;
    e->salary = salary;
}

void employ_print(employ_t *e)
{
    printf("name = %s\tid = %d\tage = %d\tsalary = %d\n", e->name, e->id, e->age, e->salary);
}

int main(int argc, char *argv)
{
    employ_t employs[3] = {0};
    employ_init(&employs[0], "abc", 1, 20, 2000);
    employ_init(&employs[1], "def", 2, 30, 3000);
    employ_init(&employs[2], "xyz", 3, 35, 4000);
    stack_t *stack = stack_create();
    stack_init(stack, sizeof(employ_t), 3);
    int i;
    for(i = 0; i < stack->size; i++){
        stack_push(stack, &employs[i], sizeof(employs[i]));
    }
    void *node;
    stack_for_each(node, stack){
        employ_print((employ_t *)node);
    }
    printf("\n==========================================\n");
    for(i = 0; i< stack->size; i++){
        employ_t ee;
        stack_pop(stack, &ee, sizeof(ee));
        employ_print(&ee);
    }
    printf("\n==========================================\n");

    return 0;
}

