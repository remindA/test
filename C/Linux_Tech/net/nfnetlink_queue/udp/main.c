#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>
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

/* 
 * #include <linux/ip.h>  --> struct iphdr;
 * #include <linux/udp.h> --> struct udphdr;
 * #include <linux/tcp.h> --> struct tcphdr;
 */
#define        IP_UDP       17
#define        IP_TCP        6

static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
int SYSTEM(const char *format, ...);
int firewall_init(unsigned short queue_port, int queue_num);
uint16_t do_csum(uint32_t __sum_init, uint8_t *buff, size_t len);
uint16_t do_tcp_csum(struct iphdr *iph, struct tcphdr *tcph);
uint16_t do_udp_csum(struct iphdr *iph, struct udphdr *udph);
uint32_t sum_pseudo_header(struct iphdr *iph, size_t len);
uint16_t do_udp_csum_recv(struct iphdr *iph, struct udphdr *udph);

int main(int argc, char **argv)
{
    if(argc != 3) {
        printf("Usage: queue_udp port queue_num\n");
        return 0;
    }
    unsigned short port = (unsigned short)atoi(argv[1]);
    int queue_num = atoi(argv[2]);

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



/* 
 * 1.   copy ethernet packet from kernel to application
 * 2.   parse ethernet packet, get ip packet
 * 3.   parse ip packet, ·ÖÆ¬ÖØ×é,»ñÈ¡get udp/tcpÕûžö°ü
 *      (don't handle tcp packet now, but must have access port)    
 * 4.   parse udp packet£¬ get sip packet.
 */

static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    printf("nfmsg->version = %d\n", nfmsg->version);
    printf("nfmsg->res_id = %d\n", ntohs(nfmsg->res_id));
#if 0
    struct nfattr **attr = (struct nfattr **)nfa->data;
#endif
    struct nfqnl_msg_packet_hdr *ph;
    u_int32_t id = 0;
    u_int32_t verdict = NF_DROP;
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
    const char *replace = "niuyaben";
    struct iphdr *iph = (struct iphdr *)payload;
    if(iph->protocol == IP_TCP) {

    }
    else if(iph->protocol == IP_UDP) {
        struct udphdr *udph = (struct udphdr *)(payload + iph->ihl*4);
        unsigned char *udp_payload = (unsigned char *)udph + sizeof(struct udphdr);
        uint16_t len_udp_payload = ntohs(udph->len) - sizeof(struct udphdr);
        //int diff = 0;
        printf("udp->check = 0x%04x\n", do_udp_csum_recv(iph, udph));
#if 1
        int diff = strlen(replace) - len_udp_payload;
        iph->tot_len = htons(ntohs(iph->tot_len) + diff);
        /* 内核netlink源码中
         * linux-3.16.57/net/netfilter/nfnetlink_queue_core.c
         * static int nfqnl_mangle(...);
         * 应用层verdict来数据之后,如果包被修改过，则
         *  e->skb->ip_summed = CHECKSUM_NONE;
         * 表明:内核会主动重新校验ip头
         * 因此: 我们只需要校验udp/tdp头即可
         */
        
        udph->len = htons(strlen(replace)+sizeof(struct udphdr));
        memcpy(udp_payload, replace, strlen(replace));
        udph->check = 0;
        udph->check = htons(do_udp_csum(iph, udph));
        printf("new udp->check 0x%04x\n", ntohs(udph->check));
        printf("new udp->check recv 0x%04x\n", do_udp_csum_recv(iph, udph));
        printf("new udp payload: %.*s", ntohs(udph->len)-sizeof(struct udphdr), udp_payload);
        /* len_of(replace) > len_of(udp_payload)目前测试过程中是没有问题的，不知原因 */
#endif
        nfq_set_verdict(qh, id, NF_ACCEPT, len_payload+diff, payload);
    }
    else {
        return nfq_set_verdict(qh, id, verdict, 0, NULL);
    }
    return nfq_set_verdict(qh, id, verdict, 0, NULL);
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

int firewall_init(unsigned short queue_port, int queue_num)
{
    SYSTEM("iptables -t mangle -F INPUT");
    SYSTEM("iptables -t mangle -F OUTPUT");
    SYSTEM("iptables -t mangle -I INPUT -p udp --dport %d -m comment --comment udp_queue -j NFQUEUE --queue-num %d", queue_port, queue_num);
    SYSTEM("iptables -t mangle -I OUTPUT -p udp --sport %d -m comment --comment udp_queue -j NFQUEUE --queue-num %d", queue_port, queue_num);
    SYSTEM("iptables -t mangle -I INPUT -p udp --dport %d -m comment --comment udp_queue -j NFQUEUE --queue-num %d", queue_port+1, queue_num+1);
    SYSTEM("iptables -t mangle -I OUTPUT -p udp --sport %d -m comment --comment udp_queue -j NFQUEUE --queue-num %d", queue_port+1, queue_num+1);

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
    printf("init: 0x%04x\n", sum);
    while(len > 1) {
        sum += ntohs(*((uint16_t *)buff));  /* ntohs需要吗 */
        printf("0x%04x\n", ntohs(*((uint16_t *)buff)));
        len  -= 2;
        buff += 2;
    }
    if(len > 0) {
        /* odd */
        /* ntohs要吗? */
        sum += ntohs((*buff) << 8);
        printf("odd: 0x%04x\n", ntohs((*buff) << 8));
    }
    
    while(sum >> 16) {
        sum = (sum >> 16) + (sum & 0x0000ffff);
    }
    return ~((uint16_t)sum);
}


uint16_t do_tcp_csum(struct iphdr *iph, struct tcphdr *tcph)
{
    tcph->check = 0;
    size_t len_tcp_tot = ntohs(iph->tot_len) - iph->ihl<<2;
    uint32_t sum = sum_pseudo_header(iph, len_tcp_tot);
    return do_csum(sum, (uint8_t *)tcph, len_tcp_tot);
}

uint16_t do_udp_csum(struct iphdr *iph, struct udphdr *udph)
{
    size_t len_udp_tot = ntohs(udph->len);
    size_t len_udp_tot2 = ntohs(iph->tot_len) - iph->ihl*4;
    if(len_udp_tot != len_udp_tot2) {
        printf("do_udp_csum: udp len err\n");
        return 0;
    }
    printf("udp_len = %d\n", len_udp_tot);
    uint32_t sum = sum_pseudo_header(iph, len_udp_tot);
    udph->check = 0;
    return do_csum(sum, (uint8_t *)udph, len_udp_tot);
}


uint16_t do_udp_csum_recv(struct iphdr *iph, struct udphdr *udph)
{
    size_t len_udp_tot = ntohs(udph->len);
    size_t len_udp_tot2 = ntohs(iph->tot_len) - iph->ihl*4;
    if(len_udp_tot != len_udp_tot2) {
        printf("do_udp_csum: udp len err, len_udp_tot = %d, len_udp_tot2 = %d\n", len_udp_tot, len_udp_tot2);
        return 0;
    }
    printf("udp_len = %d\n", len_udp_tot);
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



