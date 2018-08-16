/*
 * =====================================================================================
 *
 *       Filename:  ipset.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年07月30日 17时34分37秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#ifndef _SAA_IPSET_H_
#define _SAA_IPSET_H_

void saa_rules_init(void);
void saa_rules_add(const char *ip, const char *mac);
void saa_rules_del(const char *ip, const char *mac);
void saa_rules_flush();

#endif

