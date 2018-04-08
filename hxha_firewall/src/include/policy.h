/*
 * =====================================================================================
 *
 *       Filename:  policy.h
 *
 *    Description:  安全策略头文件定义
 *
 *        Version:  1.0
 *        Created:  2018年03月20日 12时17分17秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  NYB 
 *   Organization:  
 *
 * =====================================================================================
 */
#ifndef _FW_POLICY_H
#define _FW_POLICY_H
#include "include.h"

policy_t *create_init_policy();
struct list_head *parse_policy_list(const char *file);
int parse_ipt_proto_list(const char *str, struct list_head *head);
int parse_ipt_ipaddr_list(const char *str, struct list_head *head);
ipt_time_t *parse_ipt_time(const char *datestart, const char *datestop, const char *timestart,
        const char *timestop, const char *monthdays, const char *weekdays, const char *timezone);

void print_ipt_proto_list(struct list_head *head);
void print_ipt_ipaddr_list(struct list_head *head);
void free_policy_list(struct list_head **head);
void free_ipt_proto_list(struct list_head *head);
void free_ipt_ipaddr_list(struct list_head *head);
void free_ipt_time(ipt_time_t **time);
psd_t *build_ipt_psdstr_tabs_m(struct list_head *phead, struct list_head *shead, struct list_head *dhead);
char *build_ipt_timestr_m(ipt_time_t *time);
char *build_ipt_ipaddrstr_m(ipt_ipaddr_t *ipaddr, int is_src);
char *build_ipt_portstr_m(const char *ports, int is_src);
char *build_ipt_targetstr_m(policy_t *policy);
char *build_ipt_nataddrstr_m(int type, const char *ip, const char *port);
void free_ipt_psdstr_tabs(psd_t **tabs);
void free_ipt_policy_member(ipt_policy_t *ipt_policy);

#endif

