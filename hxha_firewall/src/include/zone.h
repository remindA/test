/*
 * =====================================================================================
 *
 *       Filename:  zone.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年03月20日 15时22分02秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#ifndef _FW_ZONE_H
#define _FW_ZONE_H
#include <uci.h>
#include "include.h"

struct list_head *parse_zone_list(const char *file);
void free_zone_list(struct list_head **head);
int  get_iface_by_network(const char *network, char *iface);
zone_t *get_zone_by_name(const char *name, struct list_head *head);


#endif

