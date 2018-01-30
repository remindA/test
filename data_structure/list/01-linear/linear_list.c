/*
 * =====================================================================================
 *
 *       Filename:  linear_ex.c
 *
 *    Description:  线性表的实现
 *
 *        Version:  1.0
 *        Created:  2018年01月02日 22时00分48秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#include "linear_list.h"


linear_list_t *linear_list_create(void)
{
    linear_list_t *list = (linear_list_t *)malloc(sizeof(linear_list_t));
    if(NULL == list){
        perror("cannot allocate memory");
        return NULL;
    }
    return (linear_list_init(list) == 0)?list:NULL;
}

int linear_list_init(linear_list_init *list)
{
    list->element = (ele_t *)malloc(sizeof(ele_t) * LINEAR_INIT_SIZE);
    if(NULL == list->element) {
        perror("cannot allocate memory");
        return -1;
    }
    list->length = 0;
    list->size   = LINEAR_INIT_SIZE;
    return 0;
}

int linear_list_add(linear_list_t *list, ele_t ele)
{

}

