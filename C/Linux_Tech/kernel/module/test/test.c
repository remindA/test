/*
 * =====================================================================================
 *
 *       Filename:  skb_linearize.c
 *
 *    Description:  测试skb_linearize是如何作用的
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
#include <linux/netfilter/nf_conntrack_common.h>



unsigned int test_hookfn(unsigned int hooknum,
        struct sk_buff *skb, 
        const struct net_device *in, 
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
#if 0
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
    char rpl_c[9] = "niuyaben";
    char rpl_s[10] = "huan_huan";

    enum ip_conntrack_info ctinfo;
    struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
    if(ct) {
        printk("nf_ct_get: ok, ctinfo = %d\n", ctinfo);
    }
    else {
        printk("nf_ct_get: NULL\n");
        return NF_ACCEPT;
    }

    if(0 != skb_linearize(skb)) {
        printk("Canot skb_linearize\n");
        //return NF_ACCEPT;
    }
    else {
        struct iphdr *iph = ip_hdr(skb);
        if(iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = tcp_hdr(skb);
            unsigned char *tcp_payload = skb->data + iph->ihl*4 + tcph->doff*4;
            int len_tcp_payload = ntohs(iph->tot_len) - iph->ihl*4 - tcph->doff*4;
            if(len_tcp_payload > 0) {
                printk("len_tcp_payload = %d, tcp_payload = %.*s\n", 
                        len_tcp_payload, len_tcp_payload, tcp_payload);
#if 0
                if(ntohs(tcph->dest) == 8080) {
                    nf_nat_mangle_tcp_packet(skb, ct, ctinfo, ip_hdrlen(skb), 
                            0, 1, rpl_c, 8);
                }
                else if(ntohs(tcph->source) == 8080) {
                    nf_nat_mangle_tcp_packet(skb, ct, ctinfo, ip_hdrlen(skb), 
                            0, 1, rpl_s, 9);
                }
#endif
            }
        }
    }

    return NF_ACCEPT;
}


static struct nf_hook_ops test_hookops = {
    .pf = NFPROTO_IPV4,
    .priority = NF_IP_PRI_MANGLE,
    //.hooknum = NF_INET_PRE_ROUTING,
    .hooknum = NF_INET_LOCAL_IN,
    .hook = test_hookfn,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
    .owner = THIS_MODULE,
#endif
};

static __init int test_init(void)
{
    /*
     * register钩子函数
     */
    printk("===== test_init =====\n");
    return nf_register_hook(&test_hookops);
}

static __exit void test_exit(void)
{
    /*
     * un-register钩子函数
     */
    printk("===== test_exit =====\n");
    nf_unregister_hook(&test_hookops);
}


MODULE_LICENSE("GPL");
module_init(test_init);
module_exit(test_exit);


