/*
 * =====================================================================================
 *
 *       Filename:  john_ring.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年04月16日 23时55分24秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#ifndef _JOHN_RING_H_
#define _JOHN_RING_H_
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "mylist.h"

typedef struct{
    int number;
    struct list_head list;
}john_t;

int do_john_ring(struct list_head *head, int step, int left);
void print_ring(struct list_head *head);
struct list_head * do_john_ring2(struct list_head *head, int step, int left);
void print_ring2(struct list_head *head);
int do_magician_card(struct list_head *head, int num);
#endif

