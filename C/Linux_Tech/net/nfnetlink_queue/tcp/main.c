#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include "mylist.h"
#include <libnfnetlink/libnfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netfilter/nf_conntrack_common.h>

/* 
 * #include <linux/ip.h>  --> struct iphdr;
 * #include <linux/udp.h> --> struct udphdr;
 * #include <linux/tcp.h> --> struct tcphdr;
 */
#define        IP_TCP        6
#define        IP_UDP       17

#if 0
/* 来自nf_conntrack_common.h */
enum ip_conntrack_info {
    /* Part of an established connection (either direction). */
    IP_CT_ESTABLISHED,

    /* Like NEW, but related to an existing connection, or ICMP error
       (in either direction). */
    IP_CT_RELATED,

    /* Started a new connection to track (only
       IP_CT_DIR_ORIGINAL); may be a retransmission. */
    IP_CT_NEW,

    /* >= this indicates reply direction */
    IP_CT_IS_REPLY,

    IP_CT_ESTABLISHED_REPLY = IP_CT_ESTABLISHED + IP_CT_IS_REPLY,
    IP_CT_RELATED_REPLY = IP_CT_RELATED + IP_CT_IS_REPLY,
    IP_CT_NEW_REPLY = IP_CT_NEW + IP_CT_IS_REPLY,	
    /* Number of distinct IP_CT types (no NEW in reply dirn). */
    IP_CT_NUMBER = IP_CT_IS_REPLY * 2 - 1
};
#endif
struct nfq_handle
{
    struct nfnl_handle *nfnlh;
    struct nfnl_subsys_handle *nfnlssh;
    struct nfq_q_handle *qh_list;
};

struct nfq_q_handle
{
    struct nfq_q_handle *next;
    struct nfq_handle *h;
    uint16_t id;

    nfq_callback *cb;
    void *data;
};

struct nfq_data {
    struct nfattr **data;  
};


const char ct_info_table[][16] = {
    [IP_CT_ESTABLISHED] = "ESTABLISHED",
    [IP_CT_RELATED] = "RELATED",
    [IP_CT_NEW] = "NEW",
    [IP_CT_IS_REPLY] = "IS_REPLY",
    [IP_CT_IS_REPLY+1] = "xxx"
};

struct tcp_point {
    int diff;
    __be32 seq;
    __be32 ack_seq;
    __be32 addr;
    __be16 port;
};

struct tcp_link {
    struct tcp_point client;
    struct tcp_point server;
    struct list_head list;
};

struct list_head head;

static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
int SYSTEM(const char *format, ...);
int firewall_init(unsigned short queue_port, int queue_num);
uint16_t do_csum(uint32_t __sum_init, uint8_t *buff, size_t len);
uint16_t do_tcp_csum(struct iphdr *iph, struct tcphdr *tcph);
uint16_t do_udp_csum(struct iphdr *iph, struct udphdr *udph);
uint32_t sum_pseudo_header(struct iphdr *iph, size_t len);
uint16_t do_tcp_csum_recv(struct iphdr *iph, struct tcphdr *tcph);
int nfq_get_ct(struct nfq_data *nfad, unsigned char **ct);
uint32_t nfq_get_ct_info(struct nfq_data *nfad);
int nfq_set_queue_flags(struct nfq_q_handle *qh,
        uint32_t mask, uint32_t flags);
int nfq_set_verdict_ct(struct nfq_q_handle *qh, uint32_t id, uint32_t verdict,
        uint32_t data_len, const unsigned char *data,
        uint32_t ct_len, const unsigned char *cf, uint32_t ct_info);

/*
 * libnetfilter_queue包含了校验的函数,所以不必再自行写校验函数
 */
int main(int argc, char **argv)
{

    if(argc != 3) {
        printf("Usage: queue_udp port queue_num\n");
        return 0;
    }
    unsigned short port = (unsigned short)atoi(argv[1]);
    int queue_num = atoi(argv[2]);
    init_list_head(&head);

    firewall_init(port, queue_num);
    /* make sure that kernel will queue packets to this app */
    int fd;
    int rv;
    struct nfq_handle *h;
    struct nfnl_handle *nh;
    struct nfq_q_handle *qh;
#if 0
    struct nfq_q_handle *qh2;
#endif
    char buf[4096] __attribute__ ((aligned));
#ifdef GB_DEBUG
    printf("opening library handle\n");
#endif
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        syslog(LOG_INFO, "in function:%s, nfq_open failed", __func__);
        exit(1);
    }

#ifdef GB_DEBUG
    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
#endif
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        syslog(LOG_INFO, "in function:%s, nfq_unbind_pf failed", __func__);
        exit(1);
    }

#ifdef GB_DEBUG
    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
#endif
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        syslog(LOG_INFO, "in function:%s, nfq_bind_pf failed", __func__);
        exit(1);
    }

#ifdef GB_DEBUG
    printf("binding this socket to queue %d\n", queue_num);
#endif
    qh = nfq_create_queue(h,  queue_num, &callback, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        syslog(LOG_INFO, "in function:%s, nfq_create_queue failed", __func__);
        exit(1);
    }

#ifdef GB_DEBUG
    printf("setting copy_packet mode\n");
#endif
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        syslog(LOG_INFO, "in function:%s, nfq_set_mode failed", __func__);
        exit(1);
    }
    if(nfq_set_queue_flags(qh, NFQA_CFG_F_CONNTRACK, NFQA_CFG_F_CONNTRACK) < 0) {
        fprintf(stderr, "cannot nfq_set_queue_flags conntrack\n");
        exit(1);
    }


#if 0
    qh2 = nfq_create_queue(h,  queue_num+1, &callback2, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        syslog(LOG_INFO, "in function:%s, nfq_create_queue failed", __func__);
        exit(1);
    }

    if (nfq_set_mode(qh2, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        syslog(LOG_INFO, "in function:%s, nfq_set_mode failed", __func__);
        exit(1);
    }
#endif

    fd = nfq_fd(h);
    syslog(LOG_INFO, "start to monitor queue packet");

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
#ifdef GB_DEBUG
        //printf("pkt received\n");
#endif
        //printf("recv %d bytes\n", rv);
        nfq_handle_packet(h, buf, rv);
    }
    printf("main: recv() < 0, This Program is gonna exit\n");
    syslog(LOG_INFO, "in function:%s, while(recv())failed", __func__);

#ifdef GB_DEBUG
    printf("unbinding from queue 0\n");
#endif
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
#ifdef GB_DEBUG
    printf("unbinding from AF_INET\n");
#endif
    nfq_unbind_pf(h, AF_INET);
#endif

#ifdef GB_DEBUG
    printf("closing library handle\n");
#endif
    nfq_close(h);

    /*
     * mainly to clean firewall rules
     */
    return 0;
}


static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    //printf("nfmsg->version = %d\n", nfmsg->version);
    //printf("nfmsg->res_id = %d\n", ntohs(nfmsg->res_id));
#if 0
    struct nfattr **attr = (struct nfattr **)nfa->data;
#endif
    struct nfqnl_msg_packet_hdr *ph;
    uint32_t id = 0;
    uint32_t verdict = NF_ACCEPT;  /* 默认放行 */
    unsigned char *payload = NULL;
    size_t len_payload = 0;
    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    }
    
    len_payload = nfq_get_payload(nfa, &payload);
    if(len_payload < 0) {
        printf("nfq_get_payload: failed\n");
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
    printf("len_payload = %d\n", len_payload);
    /* 获取ct和ctinfo */
    unsigned char *ct = NULL;
    uint32_t len_ct = 0;
    uint32_t ct_info;
    len_ct = nfq_get_ct(nfa, &ct);
    if(len_ct <= 0) {
        fprintf(stderr, "nfq_get_ct failed\n");
        len_ct = 0;
    }

    ct_info = nfq_get_ct_info(nfa);
    if(ct_info < 0) {
        fprintf(stderr, "nfq_get_ct_info failed\n");
    }
    printf("len_ct = %d, ct_info_%d = %s\n", len_ct, ct_info,
            ct_info_table[ct_info<=IP_CT_IS_REPLY?ct_info:IP_CT_IS_REPLY]);

//    return nfq_set_verdict_ct(qh, id, NF_ACCEPT, len_payload, payload, len_ct, ct, ct_info);

#if 1
    const char *replace = "niuyaben";
    const char *rpl =     "huan_huan";
    struct iphdr *iph = (struct iphdr *)payload;
    if(iph->protocol == IP_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(payload + iph->ihl*4);
        unsigned char *tcp_payload = (unsigned char *)tcph + tcph->doff*4;
        uint16_t len_tcp_payload = ntohs(iph->tot_len) - sizeof(struct iphdr) - tcph->doff*4;

#if 1
        struct list_head *pos;
        struct tcp_link *match = NULL;
        list_for_each(pos, &head) {
            struct tcp_link *link = list_entry(pos, struct tcp_link, list);
            if((link->client.addr == iph->saddr && link->client.port == tcph->source
                        && link->server.addr == iph->daddr && link->server.port == tcph->dest) || 
                    (link->server.addr == iph->saddr && link->server.port == tcph->source
                     && link->client.addr == iph->daddr && link->client.port == tcph->dest)) {
                match = link;
                printf("find match\n");
                break;
            } 
        }
        if(!match) {
            match = (struct tcp_link *)calloc(1, sizeof(struct tcp_link));
            if(NULL == match) {
                perror("calloc()");
            }
            match->client.addr = iph->saddr;
            match->client.port = tcph->source;
            match->client.diff = 0;
            match->server.addr = iph->daddr;
            match->server.port = tcph->dest;
            match->server.diff = 0;
            list_add_tail(&(match->list), &head);
            printf("no match, create tcp link\n");
        }
        if(!match) {
            return nfq_set_verdict_ct(qh, id, verdict, len_payload, payload, len_ct, ct, ct_info);
        }

#endif

        printf("%u:%u --> %u:%u\n", iph->saddr, ntohs(tcph->source), iph->daddr, ntohs(tcph->dest));

        /* 修改数据包内容 */
        int diff = 0;
        if(len_tcp_payload > 0) {
            printf("len_tcp_payload: %u\n", len_tcp_payload);
            if(match->client.addr == iph->saddr && match->client.port == tcph->source) {
                diff = -1;
                iph->tot_len = htons(ntohs(iph->tot_len) + diff);
                //len_tcp_payload = ntohs(iph->tot_len) - sizeof(struct iphdr) - tcph->doff*4;
            }
            if(match->server.addr == iph->saddr && match->server.port == tcph->source) {
                diff = -1;
                iph->tot_len = htons(ntohs(iph->tot_len) + diff);
                //len_tcp_payload = ntohs(iph->tot_len) - sizeof(struct iphdr) - tcph->doff*4;
            }
            len_tcp_payload = ntohs(iph->tot_len) - sizeof(struct iphdr) - tcph->doff*4;
            printf("new len_tcp_payload: %u\n", len_tcp_payload);
            nfq_tcp_compute_checksum_ipv4(tcph, iph);
        }
        //printf("tcp_checksum to: 0x%04x\n", ntohs(tcph->check));

        /* 
         * tcp需要重新校验
         * 1. 有payload: 包可能被修改
         * 2. 确认号/序列号修改
         */
        //printf("new tcp->check = 0x%04x\n", ntohs(tcph->check));
        //printf("new tcp->check recv = 0x%04x\n", do_tcp_csum_recv(iph, tcph));
       
        return nfq_set_verdict_ct(qh, id, NF_ACCEPT, len_payload+diff, payload, len_ct, ct, ct_info);
    }
#endif
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}


int SYSTEM(const char *format, ...)
{
    static char buf[4096]="";
    va_list arg;
    memset(buf, 0, sizeof(buf));
    va_start(arg, format);
    vsnprintf(buf,4096, format, arg);
    va_end(arg);
    system(buf);
    usleep(1000);
    return 0;

}

/*
 * 让内网可以访问外网，并且监控tcp端口的数据包
 */
int firewall_init(unsigned short queue_port, int queue_num)
{
    SYSTEM("iptables -F FORWARD");
    SYSTEM("iptables -I FORWARD -p tcp --dport %d -m state --state NEW,ESTABLISHED,RELATED"
            " -j NFQUEUE --queue-num %d", queue_port, queue_num);
    SYSTEM("iptables -I FORWARD -p tcp --sport %d -m state --state NEW,ESTABLISHED,RELATED"
            " -j NFQUEUE --queue-num %d", queue_port, queue_num);
    SYSTEM("iptables -A FORWARD -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT");
    SYSTEM("iptables -t nat -F POSTROUTING");
    SYSTEM("iptables -t nat -A POSTROUTING -j MASQUERADE");

    return 0;
}



/*
 * my checksum function
 * __sum_init: tcp/udp 虚假头
 */
uint16_t do_csum(uint32_t __sum_init, uint8_t *buff, size_t len)
{
    /* len为even, odd */
    uint32_t sum = __sum_init;
    //printf("init: 0x%04x\n", sum);
    while(len > 1) {
        sum += ntohs(*((uint16_t *)buff));  /* ntohs需要吗 */
        //printf("0x%04x\n", ntohs(*((uint16_t *)buff)));
        len  -= 2;
        buff += 2;
    }
    if(len > 0) {
        /* odd */
        sum += ntohs((*buff));
        //printf("odd: 0x%04x\n", ntohs((*buff)));
    }

    while(sum >> 16) {
        sum = (sum >> 16) + (sum & 0x0000ffff);
    }
    return ~((uint16_t)sum);
}


uint16_t do_tcp_csum(struct iphdr *iph, struct tcphdr *tcph)
{
    tcph->check = 0;
    size_t len_tcp_tot = ntohs(iph->tot_len) - iph->ihl*4;
    uint32_t sum = sum_pseudo_header(iph, len_tcp_tot);
    return do_csum(sum, (uint8_t *)tcph, len_tcp_tot);
}

uint16_t do_tcp_csum_recv(struct iphdr *iph, struct tcphdr *tcph)
{
    size_t len_tcp_tot = ntohs(iph->tot_len) - iph->ihl*4;
    uint32_t sum = sum_pseudo_header(iph, len_tcp_tot);
    return do_csum(sum, (uint8_t *)tcph, len_tcp_tot);
}

uint16_t do_udp_csum(struct iphdr *iph, struct udphdr *udph)
{
    udph->check = 0;
    size_t len_udp_tot = ntohs(udph->len);
    size_t len_udp_tot2 = ntohs(iph->tot_len) -iph->ihl*4;
    if(len_udp_tot != len_udp_tot2) {
        printf("do_udp_csum: udp len err\n");
        return 0;
    }
    uint32_t sum = sum_pseudo_header(iph, len_udp_tot);
    return do_csum(sum, (uint8_t *)udph, len_udp_tot);
}

uint16_t do_udp_csum_recv(struct iphdr *iph, struct udphdr *udph)
{
    size_t len_udp_tot = ntohs(udph->len);
    size_t len_udp_tot2 = ntohs(iph->tot_len) -iph->ihl*4;
    if(len_udp_tot != len_udp_tot2) {
        printf("do_udp_csum: udp len err\n");
        return 0;
    }
    uint32_t sum = sum_pseudo_header(iph, len_udp_tot);
    return do_csum(sum, (uint8_t *)udph, len_udp_tot);
}

uint32_t sum_pseudo_header(struct iphdr *iph, size_t len)
{
    uint32_t sum = 0;
    sum += ntohs((iph->saddr >> 16) & 0x0000ffff);
    sum += ntohs(iph->saddr & 0x0000ffff);
    sum += ntohs((iph->daddr >> 16) & 0x0000ffff);
    sum += ntohs(iph->daddr & 0x0000ffff);
    sum += iph->protocol & 0x00ff;
    sum += len;
    return sum;
}

/*
 * 对libnetfilter_queue的扩展
 */
int nfq_get_ct(struct nfq_data *nfad, unsigned char **ct)
{
#if 1
    *ct = nfnl_get_pointer_to_data(nfad->data, NFQA_CT, char);
    if(*ct) {
       // printf("nfq_get_ct: already get ct\n");
        return NFA_PAYLOAD(nfad->data[NFQA_CT-1]);  /*  */
    }
#endif
    return 0;
}

uint32_t nfq_get_ct_info(struct nfq_data *nfad)
{
    uint32_t ret = ntohl(nfnl_get_data(nfad->data, NFQA_CT_INFO, uint32_t));
   // printf("len_ct_info = %d\n", NFA_PAYLOAD(nfad->data[NFQA_CT_INFO-1]));
    return ret;
}


/*
 * 根据内核nfnetlink_queue_core.c-->nfqnl_recv_verdict()函数中
 * 只有当payload从用户空间传递到内核空间才会调用nfqnl_ct_seq_adjust();
 */
int nfq_set_verdict_ct(struct nfq_q_handle *qh, uint32_t id, uint32_t verdict,
        uint32_t data_len, const unsigned char *data,
        uint32_t ct_len, const unsigned char *ct, uint32_t ct_info)
{
    struct nfqnl_msg_verdict_hdr vh;
    union {
        char buf[NFNL_HEADER_LEN
            +NFA_LENGTH(sizeof(uint32_t)) /* for ct_info */
            +NFA_LENGTH(sizeof(vh))];     /* for verdict */
        struct nlmsghdr nmh;
    } u;

    struct iovec iov[3+2];
    int nvecs;

    /* This must be declared here (and not inside the data
     * handling block) because the iovec points to this. */
    struct nfattr data_attr;
    struct nfattr ct_attr;

    memset(iov, 0, sizeof(iov));

    vh.verdict = htonl(verdict);
    vh.id = htonl(id);

    nfnl_fill_hdr(qh->h->nfnlssh, &u.nmh, 0, AF_UNSPEC, qh->id,
            NFQNL_MSG_VERDICT, NLM_F_REQUEST);

    /* add verdict header */
    nfnl_addattr_l(&u.nmh, sizeof(u), NFQA_VERDICT_HDR, &vh, sizeof(vh));

#if 0
    if (set_mark)
        nfnl_addattr32(&u.nmh, sizeof(u), NFQA_MARK, mark);
#endif
    nfnl_addattr32(&u.nmh, sizeof(u), NFQA_CT_INFO, ct_info);

    iov[0].iov_base = &u.nmh;
    iov[0].iov_len = NLMSG_TAIL(&u.nmh) - (void *)&u.nmh;
    nvecs = 1;

    if (data_len) {
        /* The typecast here is to cast away data's const-ness: */
        nfnl_build_nfa_iovec(&iov[nvecs], &data_attr, NFQA_PAYLOAD,
                data_len, (unsigned char *) data);
        nvecs += 2;
        /* Add the length of the appended data to the message
         * header.  The size of the attribute is given in the
         * nfa_len field and is set in the nfnl_build_nfa_iovec()
         * function. */
        u.nmh.nlmsg_len += data_attr.nfa_len;
        if(ct_len && ct) {
            nfnl_build_nfa_iovec(&iov[nvecs], &ct_attr, NFQA_CT,
                    ct_len, (unsigned char *)ct);
            nvecs += 2;
        }
    }
    printf("nvecs = %d\n", nvecs);
    int ret = nfnl_sendiov(qh->h->nfnlh, iov, nvecs, 0);
    //printf("nfq_set_verdict_ct: ret = %d\n", ret);
    
    return ret;
}

#if 0
static int __set_verdict(struct nfq_q_handle *qh, uint32_t id,
        uint32_t verdict, uint32_t mark, int set_mark,
        uint32_t data_len, const unsigned char *data,
        enum nfqnl_msg_types type)
{
    struct nfqnl_msg_verdict_hdr vh;
    union {
        char buf[NFNL_HEADER_LEN
            +NFA_LENGTH(sizeof(mark))
            +NFA_LENGTH(sizeof(vh))];
        struct nlmsghdr nmh;
    } u;

    struct iovec iov[3];
    int nvecs;

    /* This must be declared here (and not inside the data
     * handling block) because the iovec points to this. */
    struct nfattr data_attr;

    memset(iov, 0, sizeof(iov));

    vh.verdict = htonl(verdict);
    vh.id = htonl(id);

    nfnl_fill_hdr(qh->h->nfnlssh, &u.nmh, 0, AF_UNSPEC, qh->id,
            type, NLM_F_REQUEST);

    /* add verdict header */
    nfnl_addattr_l(&u.nmh, sizeof(u), NFQA_VERDICT_HDR, &vh, sizeof(vh));

    if (set_mark)
        nfnl_addattr32(&u.nmh, sizeof(u), NFQA_MARK, mark);

    iov[0].iov_base = &u.nmh;
    iov[0].iov_len = NLMSG_TAIL(&u.nmh) - (void *)&u.nmh;
    nvecs = 1;

    if (data_len) {
        /* The typecast here is to cast away data's const-ness: */
        nfnl_build_nfa_iovec(&iov[1], &data_attr, NFQA_PAYLOAD,
                data_len, (unsigned char *) data);
        nvecs += 2;
        /* Add the length of the appended data to the message
         * header.  The size of the attribute is given in the
         * nfa_len field and is set in the nfnl_build_nfa_iovec()
         * function. */
        u.nmh.nlmsg_len += data_attr.nfa_len;
    }

    return nfnl_sendiov(qh->h->nfnlh, iov, nvecs, 0);
}

#endif

