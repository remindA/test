#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
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
#include <libnfnetlink/libnfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netfilter/nf_conntrack_common.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>

#include "list.h"

/* 
 * #include <linux/ip.h>  --> struct iphdr;
 * #include <linux/udp.h> --> struct udphdr;
 * #include <linux/tcp.h> --> struct tcphdr;
 */
#define IP_TCP  6
#define IP_UDP  17


static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
int SYSTEM(const char *format, ...);
int firewall_init(unsigned short queue_port, int queue_num);

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

    fd = nfq_fd(h);
    syslog(LOG_INFO, "start to monitor queue packet");

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
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

static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *d)
{
    struct nfqnl_msg_packet_hdr *ph;
    uint32_t id = 0;
    unsigned char *pkt = NULL;
    size_t len_pkt = 0;
    ph = nfq_get_msg_packet_hdr(nfa);
    if(ph){
        id = ntohl(ph->packet_id);
    }

    len_pkt = nfq_get_payload(nfa, &pkt);
    if(len_pkt < 0) {
        printf("nfq_get_payload: failed\n");
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    printf("len_pkt = %d\n", len_pkt);

    struct iphdr *iph = (struct iphdr *)pkt;
    if(iph->protocol == IP_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(pkt + iph->ihl*4);
        unsigned char *data = (unsigned char *)tcph + tcph->doff*4;
        uint16_t len_data = ntohs(iph->tot_len) - sizeof(struct iphdr) - tcph->doff*4;
        if(!len_data) {
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        }
        /* group by class */

        int diff = 0;
        printf("len_data=%d > 0\n", len_data);
        const char *rpl = "huanhuan";
        int len_rpl = strlen(rpl);
        diff = len_rpl - len_data;
        if(diff <= 0) {
            /* shrink: won't malloc */ 
            iph->tot_len = htons(ntohs(iph->tot_len) + diff);
            memcpy(data, rpl, len_rpl);

            nfq_ip_set_checksum(iph);
            nfq_tcp_compute_checksum_ipv4(tcph, iph);
            return nfq_set_verdict(qh, id, NF_ACCEPT, len_pkt+diff, pkt);
        }
        else {
            /* enlarge: must malloc */
            unsigned char *new_pkt = (unsigned char *)malloc(len_pkt+diff);
            memcpy(new_pkt, pkt, len_pkt+diff);
            struct iphdr *new_iph = (struct iphdr *)new_pkt;
            struct tcphdr *new_tcph = (struct tcphdr *)(new_pkt + new_iph->ihl*4);
            unsigned char *new_data = (unsigned char *)new_tcph + new_tcph->doff*4;
            new_iph->tot_len = htons(ntohs(new_iph->tot_len)+diff);
            memcpy(new_data, rpl, len_rpl);

            nfq_ip_set_checksum(new_iph);
            nfq_tcp_compute_checksum_ipv4(new_tcph, new_iph);
            int ret = nfq_set_verdict(qh, id, NF_ACCEPT, len_pkt+diff, new_pkt);
            free(new_pkt);
            return ret;
        }
    }
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
    /* 再mangle表中修改数据 */
    SYSTEM("iptables -F FORWARD");
    SYSTEM("iptables -P FORWARD ACCEPT");
    SYSTEM("iptables -t nat -F POSTROUTING");
    SYSTEM("iptables -t nat -F POSTROUTING");
    /* 目标端口是queue_port的数据包改包 */
#if 1
    SYSTEM("iptables -t mangle -F FORWARD");
    SYSTEM("iptables -t mangle -F FORWARD");
    SYSTEM("iptables -t mangle -I FORWARD -p tcp --dport %d"
            " -j NFQUEUE --queue-num %d", queue_port, queue_num);
    SYSTEM("iptables -t mangle -I FORWARD -p tcp --sport %d"
            " -j NFQUEUE --queue-num %d", queue_port, queue_num);
#endif
#if 0
    SYSTEM("iptables -t mangle -F POSTROUTING");
    SYSTEM("iptables -t mangle -F POSTROUTING");
    SYSTEM("iptables -t mangle -I POSTROUTING -p tcp --dport %d"
            " -j NFQUEUE --queue-num %d", queue_port, queue_num);
    SYSTEM("iptables -t mangle -I POSTROUTING -p tcp --sport %d"
            " -j NFQUEUE --queue-num %d", queue_port, queue_num);
#endif
    SYSTEM("iptables -t nat -A POSTROUTING -j MASQUERADE");

    return 0;
}



