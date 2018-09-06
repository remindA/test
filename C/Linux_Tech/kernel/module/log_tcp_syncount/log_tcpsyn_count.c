/*
 * =====================================================================================
 *
 *       Filename:  log_tcpsyn_count.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年08月29日 21时40分02秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  NYB (), niuyabeng@126.com
 *   Organization:  
 *
 * =====================================================================================
 */


#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/moduleparam.h>

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <net/tcp.h>
#include <net/udp.h>
#include <net/sock.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_helper.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_expect.h>


static unsigned long count = 0;

unsigned int log_tcpsyn_count_hookfn(const struct nf_hook_ops *ops,
        struct sk_buff *skb, 
        const struct net_device *in, 
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
#if 1
    /* 如果syn置位，count++ */
    struct iphdr *iph = ip_hdr(skb);
    if(iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = tcp_hdr(skb);
        if(ntohs(tcph->dest) == 1995 && tcph->syn) {
            count++;
            printk("syn count to %u is %lu\n", ntohs(tcph->dest), count);
        }
    }
#endif
    //printk("==== in log_tcpsyn_count_hookfn =====\n");

    return NF_ACCEPT;
}


static struct nf_hook_ops log_tcpsyn_count_hookops = {
    .pf = NFPROTO_IPV4,
    .priority = NF_IP_PRI_FIRST,
    .hooknum = NF_INET_PRE_ROUTING,
    .hook = log_tcpsyn_count_hookfn,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
    .owner = THIS_MODULE,
#endif
};

static __init int log_tcpsyn_count_init(void)
{
    /*
     * register钩子函数
     */
    printk("===== log_tcpsyn_count_init =====\n");
    return nf_register_hook(&log_tcpsyn_count_hookops);
}

static __exit void log_tcpsyn_count_exit(void)
{
    /*
     * un-register钩子函数
     */
    printk("===== log_tcpsyn_count_exit =====\n");
    nf_unregister_hook(&log_tcpsyn_count_hookops);
}


MODULE_LICENSE("GPL");
module_init(log_tcpsyn_count_init);
module_exit(log_tcpsyn_count_exit);


