/*
 * =====================================================================================
 *
 *       Filename:  pool.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年04月08日 13时51分30秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#ifndef _FW_POOL_H_
#define _FW_POOL_H_
#include "include.h"

struct list_head *parse_pool_list(const char *file);
void free_pool_list(struct list_head **head);
pool_t *get_pool_by_name(struct list_head *head, const char *name);

#endif

