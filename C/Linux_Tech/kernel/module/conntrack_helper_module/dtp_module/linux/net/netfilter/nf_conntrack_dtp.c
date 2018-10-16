/*
 * =====================================================================================
 *
 *       Filename:  nf_conntrack_dtp.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年10月11日 15时07分02秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/moduleparam.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/inet.h>
#include <linux/netfilter.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_tuple.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_ecache.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <linux/netfilter/nf_conntrack_dtp.h>

MODULE_AUTHOR("NYB <niuyabeng@126.com>");
MODULE_DESCRIPTION("DTP connection tracking helper");
MODULE_LICENSE("GPL");
MODULE_ALIAS("nf_conntrack_dtp");

static unsigned short port = DTP_PORT;
module_param(port, ushort, 0400);
MODULE_PARM_DESC(port, "Port number of DTP Server");

/*
 * __read_mostly: 把数据放入到cache中提高系统执行效率
 * 这个模块内定义的函数要被另外一个模块调用，则要用EXPORT_SYMBOL导出来
 * 然后在调用模块中extern 一下函数接口，就可以使用了
 */

/* 
 * 下面形式的函数在net/ipv4/netfilter/nf_nat_dtp.c中定义的
 * 如果要想在此文件中调用，须声明起原型，并使用EXPORT_SYMBOL_GPL() 
 * 同时在头文件/include/linux/netfilter/nf_conntrack_dtp.h中extern声明
 */
unsigned int (*nf_nat_dtp_hook)(struct sk_buff *skb, unsigned int protoff,
            unsigned int dataoff, unsigned int *datalen, char **data,
            struct nf_conntrack_expect *exp, 
            unsigned int port_off,   unsigned int port_len,
            unsigned int ipaddr_off, unsigned int ipaddr_len,
            union nf_inet_addr *addr) __read_mostly;
EXPORT_SYMBOL_GPL(nf_nat_dtp_hook);


static int nf_dtp_get_addr(unsigned int dataoff, unsigned int datalen, char *data,
            unsigned int *port_off,   unsigned int *port_len,   unsigned short *port,
            unsigned int *ipaddr_off, unsigned int *ipaddr_len, union nf_inet_addr *ipaddr)
{
    if('A' != data[0]) {
        return -1;
    }
    if(datalen > strlen("A255.255.255.255:65535")) {
        return -1;
    }
    
    char *split = strchr(data, ':');
    if(NULL == split) {
        return -1;
    }
    char *ip_st = data + 1;
    char *port_st = split + 1;
    memset(ipaddr, 0, sizeof(*ipaddr));
    const char *end;
    
    if(0 == in4_pton(ip_st, split - ip_st, (u8 *)&ipaddr->ip, -1, &end)) {
        printk(KERN_EMERG"nf_dtp_get_addr: in4_pton failed\n");
        return -1;
    }
    *port = (unsigned short)simple_strtoul(port_st, NULL, 10);  /* 10代表十进制 */
    *port = htons(*port);
    *ipaddr_off = 1;
    *ipaddr_len = split - ip_st;
    *port_off = 1 + *ipaddr_len + 1;
    *port_len = datalen - 1 - 1 - *ipaddr_len;
    printk(KERN_EMERG"nf_dtp_get_addr: %.*s:%.*s\n", 
            *ipaddr_len, ip_st, *port_len, port_st);
    printk(KERN_EMERG"nf_dtp_get_addr:\n\taddr_off = %hu, addr_len = %hu\n\tport_off = %hu, port_len = %hu\n",
            *ipaddr_off, *ipaddr_len, *port_off, *port_len);

    printk(KERN_EMERG"nf_dtp_get_addr: %u.%u.%u.%u:%hu\n", 
            NIPQUAD(ipaddr->ip), ntohs(*port));

    return 1;
}


static int set_expected_dtp(struct sk_buff *skb, unsigned int protoff,
                    unsigned int dataoff, unsigned int *datalen, char **data)
{
    int ret = NF_DROP;
    enum ip_conntrack_info ctinfo;
    struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
    enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
    //struct net *net = nf_ct_net(ct);
    struct nf_conntrack_expect *data_exp;
    struct nf_conntrack_tuple tuple;
    unsigned short port;
    union nf_inet_addr ipaddr;
    unsigned int port_off = 0, port_len = 0;
    unsigned int ipaddr_off = 0, ipaddr_len = 0;
    typeof(nf_nat_dtp_hook) nat_dtp;

    printk(KERN_EMERG"set_expexted_dtp: start\n");
    
    memset(&ipaddr, 0, sizeof(ipaddr));
    if(nf_dtp_get_addr(dataoff, *datalen, *data,
                &port_off, &port_len, &port,
                &ipaddr_off, &ipaddr_len, &ipaddr) < 0) {
        return NF_ACCEPT;
    }

    memset(&tuple, 0, sizeof(tuple));
    tuple.src.l3num = nf_ct_l3num(ct);
    tuple.dst.protonum = IPPROTO_UDP;
    tuple.dst.u3 = ipaddr;
    tuple.dst.u.udp.port = port;
    /* Aip:port, 先更新port,再更新ip,否则先更新完ip, port的off就失效了 */
    /*
     * 1. 查询此连接是否UI经有了exp连接(udp同一个信令可能会传输多次，不能重复建立exp)
     * 2. 有exp:则仍然要替换字符串ip:port(sip模块可能是有bug的。函数set_expected_rtp_rtcp())
     * 3. 无exp:建立，初始化
     */
#if 0
    重复先不检查:目前假设udp信令不丢包
    do {
        data_exp = __nf_ct_expect_find(net, nf_ct_zone(ct), &tuple);
        if(!data_exp || data_exp->master == ct || 
            nf_ct_help(data_exp->master)->helper != nfct_help(ct)->helper ||
            data_exp->class != class) {
            /* 不存在exp */
            break;
        }
        
    }while();
#endif
    printk(KERN_EMERG"set_expexted_dtp: create exp\n");
    data_exp = nf_ct_expect_alloc(ct);
    if(NULL ==  data_exp) {
        goto err1;
    }
    /* 
     * 初始化的exp: 10.10.10.231:NULL --> 192.168.1.100:12345
     * 最终预期exp: 10.10.10.231:NULL --> 10.10.10.38:xxxx(12345)
     */
    nf_ct_expect_init(data_exp, NF_CT_EXPECT_CLASS_DEFAULT, nf_ct_l3num(ct),
             NULL, &ipaddr, IPPROTO_UDP, NULL, &port);
    printk(KERN_EMERG"set_expexted_dtp: exp init" 
            "%u.%u.%u.%u:%hu --> %u.%u.%u.%u:%hu\n",
            NIPQUAD(data_exp->tuple.src.u3.ip), ntohs(data_exp->tuple.src.u.udp.port),
            NIPQUAD(data_exp->tuple.dst.u3.ip), ntohs(data_exp->tuple.dst.u.udp.port));
    
    nat_dtp = rcu_dereference(nf_nat_dtp_hook);
    if(nat_dtp && ct->status & IPS_NAT_MASK) {
        /* 
         * nat_dtp会做好nat的工作，
         * 并把port字符串替换成nated_port字符串
         * 并把ip字符串替换为出接口地址
         * nat_dtp()中调用了nf_ct_expect_related(),
         *      失败时会调用nf_ct_unexpect_related()
         */
        ret = nat_dtp(skb, protoff, 
                dataoff, datalen, data, 
                data_exp, 
                port_off, port_len, 
                ipaddr_off, ipaddr_len,
                &ipaddr);
    }
    else {
        if(nf_ct_expect_related(data_exp) == 0) {
            nf_ct_unexpect_related(data_exp);
        }
    }

    /* 
     * nf_ct_expect_related(); 会把exp->use增一
     * exp->use减一后，为0时, 会有释放内存操作
     */
    nf_ct_expect_put(data_exp);  
err1:
    printk(KERN_EMERG"set_expexted_dtp: finsh\n");
    return ret;
}

static int process_dtp_address(struct sk_buff *skb, unsigned int protoff,
                unsigned int dataoff, unsigned int *datalen, char **data)
{
    return set_expected_dtp(skb, protoff, dataoff, datalen, data);
}


static int dtp_help(struct sk_buff *skb,
        unsigned int protoff,
        struct nf_conn *ct,
        enum ip_conntrack_info ctinfo)
{
    int ret;

    char *data = NULL;
    unsigned int dataoff = 0;
    unsigned int datalen = 0;
    //printk(KERN_EMERG"dtp_help: start\n");

    dataoff = protoff + sizeof(struct udphdr);
    /* skb->len是data的长度 */
    if(dataoff >= skb->len) {
        return NF_ACCEPT;
    }

    /* 刷新连接的超时时间 */
    nf_ct_refresh(ct, skb, 360 * HZ);
    if(unlikely(skb_linearize(skb))) {
        return NF_DROP;
    }
    
    data = skb->data + dataoff;
    datalen = skb->len - dataoff;

    if(datalen <= 1 || 'A' != data[0]) {
        /*
         * H: Hello
         * K: addr ack
         * E: end
         * D: data
         */
        return NF_ACCEPT;
    }

    /* 下面处理是A: Address */
    printk(KERN_EMERG"dtp_help: will process_dtp_address\n");
    ret = process_dtp_address(skb, protoff, dataoff, &datalen, &data);
    
    printk(KERN_EMERG"dtp_help: finish\n");
    return ret;
}


static char dtp_buff[1024];
static const struct nf_conntrack_expect_policy dtp_exp_policy = {
    .max_expected = 32,
    .timeout = 360,
};
static struct nf_conntrack_helper nf_conntrack_helper_dtp __read_mostly = {
    .name = "DTP",                             /* helper的名称 */
    .me = THIS_MODULE,
    .tuple.src.l3num = AF_INET,                /* ipv4 */
    .tuple.src.u.udp.port = htons(DTP_PORT),   /* 端口 */
    .tuple.dst.protonum = IPPROTO_UDP,         /* UDP */
    .help = dtp_help,                          /* help函数 */
    .expect_policy = &dtp_exp_policy,
};

static int __init nf_conntrack_dtp_init(void)
{
    int ret;
    memset(dtp_buff, 0, sizeof(dtp_buff)); /* 暂时没有用到dtp_buff */
    /* 注册helper: 插入链表 */
    ret = nf_conntrack_helper_register(&nf_conntrack_helper_dtp);
    if(ret < 0) {
        goto err;
    }
    printk(KERN_EMERG"nf_conntrack_dtp_init: port= %d\n", port);
    return 0;
err:
    printk(KERN_EMERG"nf_conntrack_dtp_init: failed\n");
    return ret;
}

static void __exit nf_conntrack_dtp_exit(void)
{
    /* 注销helper: 从链表上移除 */
    nf_conntrack_helper_unregister(&nf_conntrack_helper_dtp);
    printk(KERN_EMERG"nf_conntrack_dtp_exit: exit\n");
}


module_init(nf_conntrack_dtp_init);
module_exit(nf_conntrack_dtp_exit);

