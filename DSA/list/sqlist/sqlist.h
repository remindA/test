/*
 * =====================================================================================
 *
 *       Filename:  sqlist.h
 *
 *    Description:  线性表顺序存储
 *
 *        Version:  1.0
 *        Created:  2018年03月31日 20时05分57秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

/* 
 * 优点
 *      1.　无需为表示元素之间的逻辑关系增加额外存储空间
 *      2.  ***快速查找任意位置元素
 * 缺点
 *      1.  ***插入/删除要移动大量元素
 *      2.  表长度变化较大时，难以确定存储空间
 *      3.  存储空间“碎片”
 *
 */

#ifndef _SQ_LIST_H_
#define _SQ_LIST_H_
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <error.h>

#define SQLIST_MAX_SIZE 1024

typedef int elem_t;

typedef struct {
    int len;
    elem_t elem[SQLIST_MAX_SIZE];
}sqlist_t;



#endif

