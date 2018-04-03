/*
 * =====================================================================================
 *
 *       Filename:  iptables.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年03月30日 11时38分20秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#ifndef _FW_IPTABLES_H
#define _FW_IPTABLES_H
#include "zone.h"
#include "policy.h"
#include "include.h"

typedef void (*policy_print)(policy_t *policy);
extern policy_print print_fun_tabs[];
typedef void(*sighandler_t)(int);

void ipt_init_print(void);
void ipt_zone_print(struct list_head *head);
void ipt_policy_print(struct list_head *head, int type);
void ipt_policy_local_print(policy_t *policy);
void ipt_policy_forward_print(policy_t *policy);
void ipt_policy_snat_print(policy_t *policy);
void ipt_policy_dnat_print(policy_t *policy);

ssize_t my_write(int fd, const void *buf, size_t count);
int make_fw_run_script(char *file, struct list_head *zhead, struct list_head *phead);
int make_fw_flush_script(char *file, struct list_head *zhead);
int write_iptables_init(int fd);
int write_iptables_zone(int fd, struct list_head *head);
int write_iptables_policy(int fd, struct list_head *head);
int write_iptables_local(int fd, policy_t *policy);
int write_iptables_forward(int fd, policy_t *policy);
int write_iptables_dnat(int fd, policy_t *policy);
int write_iptables_snat(int fd, policy_t *policy);
int iptables_run_script(const char *file);
#endif

