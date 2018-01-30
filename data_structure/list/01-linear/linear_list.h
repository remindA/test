/*
 * =====================================================================================
 *
 *       Filename:  linear_ex.h
 *
 *    Description:  数组表示线性表
 *
 *        Version:  1.0
 *        Created:  2018年01月02日 21时57分55秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#ifndef _LINER_H_
#define _LINER_H_
#include "safe_free.h"

#define LINEAR_INIT_SIZE  100   //初始线性表大小100
#define LINEAR_STEP_SIZE  20    //线性表不够用时，增量20

typedef struct {
    int num;
} elt_t;

typedef struct _linear_list{
    ele_t *element;
    int   length;
    int   size;
} linear_list_t;

linear_list_t *linear_list_create(void);
int  linear_list_init(linear_list_init *list);

int linear_list_add(linear_list_t *list, ele_t ele);




#endif

