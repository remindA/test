/*
 * =====================================================================================
 *
 *       Filename:  config.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年07月27日 17时33分57秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#ifndef _SAA_CONFIG_H_
#define _SAA_CONFIG_H_
#include "mylist.h"
#include "protocol.h"

typedef struct {
    char auth_state[2];              /* GUI */
    char ip[LEN_IP_STR];             /* 17 bytes, what if through a NAT device */
    char mac[LEN_MAC_STR];           /* bytes */
    char mach_code[LEN_MACH_CODE];   /* 16 bytes */
    char auth_code[LEN_AUTH_CODE];   /* 16 bytes */
    char mark[LEN_MARK];             /* should be short */
    unsigned long online_tstamp;     /* lastest time */
    unsigned char access_switch;     /* won't appear in config file */
    struct list_head list;
}saa_entry_t；


int read_config_yes(const char *config, struct list_head *head);
int read_config_no(const char *filepath, struct list_head *head);
int parse_entry(const char *line, saa_entry_t *entry);
void update_unauth_file(struct list_head *head_no,  const char *config_file_no);

#endif

