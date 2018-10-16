/*
 * =====================================================================================
 *
 *       Filename:  nf_conntrack_dtp.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年10月11日 15时09分18秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#ifndef _NF_CONNTRACK_DTP_H_
#define _NF_CONNTRACK_DTP_H_

#define DTP_PORT 18080


extern unsigned int (*nf_nat_dtp_hook)(struct sk_buff *skb, unsigned int protoff,
            unsigned int dataoff, unsigned int *datalen, char **data,
            struct nf_conntrack_expect *exp, 
            unsigned int port_off, unsigned int port_len,
            unsigned int ipaddr_off, unsigned int ipaddr_len,
            union nf_inet_addr *addr);

#endif

