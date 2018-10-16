/*
 * =====================================================================================
 *
 *       Filename:  nf_nat_dtp.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年10月11日 15时08分59秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/ctype.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/inet.h>
#include <linux/netfilter.h>
#include <net/ip.h>

#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_helper.h>
#include <net/netfilter/nf_nat_rule.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <linux/netfilter/nf_conntrack_dtp.h>

MODULE_AUTHOR("NYB <niuyabeng@126.com>");
MODULE_DESCRIPTION("DTP NAT helper");
MODULE_LICENSE("GPL");
MODULE_ALIAS("nf_nat_dtp");


static unsigned int mangle_packet(struct sk_buff *skb,
        const char **dptr, unsigned int *datalen,
        unsigned int matchoff, unsigned int matchlen,
        const char *buffer, unsigned int buflen)
{
    enum ip_conntrack_info ctinfo;
    struct nf_conn *ct = nf_ct_get(skb, &ctinfo);

    if(0 == nf_nat_mangle_udp_packet(skb, ct, ctinfo, matchoff, matchlen,
                buffer, buflen)) {
        return 0;
    }

    /* Reload data pointer and adjust datalen value */
    *dptr = skb->data + ip_hdrlen(skb) + sizeof(struct udphdr);
    *datalen += buflen - matchlen;
    return 1;
}

/* 
 * 这里调用的函数给nf_conntrack_dtp来使用，对ip:port做替换
 * 真正的DNAT和SNAT工作由ip_nat_dtp_expect()来做
 * 期望连接的第一个数据包会经过这个函数，随后根据exp建立ct，然后删除exp
 */
static void nf_nat_dtp_expected(struct nf_conn *ct,
        struct nf_conntrack_expect *exp)
{
    struct nf_nat_range range;
    printk(KERN_EMERG"nf_nat_dtp_expected: start\n");
    BUG_ON(ct->status & IPS_NAT_DONE_MASK); 

    memset(&range, 0, sizeof(range));
    /* DNAT */
    /* 
     * flags指明要nat的信息为MAP_IPS和PROTO_SPECIFIED
     * flags没有置位MAP_IPS，那么就不会发生DNAT和SNAT
     */
    range.flags = (IP_NAT_RANGE_MAP_IPS | IP_NAT_RANGE_PROTO_SPECIFIED);
    range.min = range.max = exp->saved_proto;
    range.min_ip = range.max_ip = exp->saved_ip;
    nf_nat_setup_info(ct, &range, IP_NAT_MANIP_DST);
    printk(KERN_EMERG"nf_nat_dtp_expected: DNAT --> %u.%u.%u.%u:%hu\n",
            NIPQUAD(range.min_ip), ntohs(range.min.udp.port));

#if 1
    /* SNAT: 代码来自sip模块 */
    /* 
     * 这里的range.min_ip和range.max_ip适用于给予地址映射方式接入
     * 当Linux作为防火墙时,代码参考sip模块
     */
    range.flags = IP_NAT_RANGE_MAP_IPS;
    range.min_ip = range.max_ip
        = ct->master->tuplehash[!exp->dir].tuple.dst.u3.ip;
    nf_nat_setup_info(ct, &range, IP_NAT_MANIP_SRC);
    printk(KERN_EMERG"nf_nat_dtp_expected: SNAT --> %u.%u.%u.%u:%hu\n",
            NIPQUAD(range.min_ip), ntohs(range.min.udp.port));
#endif

    printk(KERN_EMERG"nf_nat_dtp_expected: finish\n");
}


static unsigned int nf_mangle_dtp_port(struct sk_buff *skb, unsigned int protoff,
        unsigned int dataoff, unsigned int *datalen, char **data,
        unsigned int port_off, unsigned int port_len,
        u_int16_t nated_port)    /* 已经ntohs() */
{
    char str[sizeof("65535")] = {0};
    unsigned int len = sprintf(str, "%u", nated_port);
    return mangle_packet(skb, (const char **)data, datalen, 
            port_off, port_len, str, len);
}

static unsigned int nf_mangle_dtp_ip(struct sk_buff *skb, unsigned int protoff,
        unsigned int dataoff, unsigned int *datalen, char **data,
        unsigned int ipaddr_off, unsigned int ipaddr_len,
        const union nf_inet_addr *ipaddr)
{
    enum ip_conntrack_info ctinfo;
    struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
    char str[sizeof("255.255.255.255")] = {0};
    unsigned int len;

    /* 在最开始时直接放行ipv6包 */
    len = sprintf(str, NIPQUAD_FMT, NIPQUAD(ipaddr->ip));
    printk(KERN_EMERG"nf_mangle_dtp_ip: ip = %.*s\n", len, str);
    return mangle_packet(skb, (const char **)data, datalen,
            ipaddr_off, ipaddr_len, str, len);
}

static unsigned int nat_dtp(struct sk_buff *skb, unsigned int protoff,
        unsigned int dataoff, unsigned int *datalen, char **data,
        struct nf_conntrack_expect *exp, 
        unsigned int port_off, unsigned int port_len,
        unsigned int ipaddr_off, unsigned int ipaddr_len,
        union nf_inet_addr *addr)
{
    enum ip_conntrack_info ctinfo;
    struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
    enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
    u_int16_t nated_port;
    union nf_inet_addr ipaddr_old = *addr;

    //printk(KERN_EMERG"nat_dtp: start\n");
    if(nf_inet_addr_cmp(&ct->tuplehash[dir].tuple.src.u3, 
                &ct->tuplehash[!dir].tuple.dst.u3)) {
        *addr = exp->tuple.dst.u3;  /* 192.168.1.100:12345 */
    }
    else {
        /*
         * dir: 10.10.10.38 --> 10.10.10.231
         * !dir: 10.10.10.231 --> 192.168.1.100
         */
        *addr = ct->tuplehash[!dir].tuple.dst.u3; /* 10.10.10.38 */
    }

    exp->saved_ip = exp->tuple.dst.u3.ip;  /* 192.168.1.100保存 */
    exp->tuple.dst.u3.ip = addr->ip;            /* 192.168.1.100 --> 10.10.10.38 */
    exp->saved_proto.udp.port = exp->tuple.dst.u.udp.port;
    exp->dir = !dir;
    exp->expectfn = nf_nat_dtp_expected;

    /* try to get the same port, if not change it */
    //printk(KERN_EMERG"nat_dtp: get nated_port\n");
    unsigned short port;
    for(port = nated_port = ntohs(exp->tuple.dst.u.udp.port);
            nated_port != 0; nated_port++) {
        int ret;
        exp->tuple.dst.u.udp.port = htons(nated_port);
        /* 调用nf_ct_expect_related()会把ip:port给占用住 */
        ret = nf_ct_expect_related(exp);
        /* -EBUSY说明这个端口被占用了 */
        if(ret == -EBUSY) {
            continue;
        }
        else if(ret < 0) {
            nated_port = 0;
            break;
        }
        else {
            break;
        }
    }
    if(0 == nated_port) {
        printk(KERN_EMERG"nat_dtp: cannot get nated_port\n");
        goto err1;
    }

    /* 若端口不相等: 修改报文中的port为nated_port */

    //if(exp->saved_proto.udp.port != exp->tuple.dst.u.udp.port &&
    if(0 == nf_mangle_dtp_port(skb, protoff, dataoff, datalen, data, 
                port_off, port_len, nated_port)) {
        printk("nat_dtp: cannot mangle data port: %hu --> %hu\n", port, nated_port);
        goto err2;
    }
    printk(KERN_EMERG"nat_dtp: DONE mangle data port: %hu --> %hu\n", port, nated_port);

    /* 再来修改ip字符串 */
    if(0 == nf_mangle_dtp_ip(skb, protoff, dataoff, datalen, data,
                ipaddr_off, ipaddr_len, addr)) {
        printk(KERN_EMERG"nat_dtp: cannot mangle data ip: %u.%u.%u.%u --> %u.%u.%u.%u\n",
                NIPQUAD(ipaddr_old.ip), NIPQUAD(addr->ip));
        goto err2;
    }
    printk(KERN_EMERG"nat_dtp: DONE mangle data ip: %u.%u.%u.%u --> %u.%u.%u.%u\n",
            NIPQUAD(ipaddr_old.ip), NIPQUAD(addr->ip));
    printk(KERN_EMERG"nat_dtp: exp init" 
            "%u.%u.%u.%u:NULL --> %u.%u.%u.%u:%hu\n",
            NIPQUAD(exp->tuple.src.u3.ip), ntohs(exp->tuple.src.u.udp.port),
            NIPQUAD(exp->tuple.dst.u3.ip), ntohs(exp->tuple.dst.u.udp.port));
    printk(KERN_EMERG"nat_dtp: finish\n");
    return NF_ACCEPT;

err2:
    nf_ct_unexpect_related(exp);
err1:
    return NF_DROP;
}

static int __init nf_nat_dtp_init(void)
{
    printk(KERN_EMERG"nf_nat_dtp_init: start\n");
    BUG_ON(nf_nat_dtp_hook != NULL);
    /* 
     * RCU机制: 将nat_dtp发布到nf_nat_dtp_hook上
     * 当需要使用时
     * rcu_read_lock();
     * nat_dtp = rcu_dereference(nf_nat_dtp_hook);
     * nat_dtp(...);
     * rcu_read_unlock();
     */
    rcu_assign_pointer(nf_nat_dtp_hook, nat_dtp); 
    printk(KERN_EMERG"nf_nat_dtp_init: finish\n");
    return 0;
}

static void __exit nf_nat_dtp_exit(void)
{
    printk(KERN_EMERG"nf_nat_dtp_exit: start\n");
    rcu_assign_pointer(nf_nat_dtp_hook, NULL);
    synchronize_rcu();
    printk(KERN_EMERG"nf_nat_dtp_exit: finish\n");
}

module_init(nf_nat_dtp_init);
module_exit(nf_nat_dtp_exit);



