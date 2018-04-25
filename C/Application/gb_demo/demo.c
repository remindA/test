
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */

#include <libnetfilter_queue/libnetfilter_queue.h>

#ifdef DEMO
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux.tcp.h>
#include <arpa/inet.h>

/* #include <linux/ip.h>
 * struct iphdr;
 * 
 * #include <linux/udp.h>
 * struct udphdr;
 *
 * #include <linux/tcp.h>
 * struct tcphdr;
 */
#ifdef __LITTLE_ENDIAN
#define IPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[3]
#else
#define IPQUAD(addr) \
    ((unsigned char *)&addr)[3], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[0]
#endif

#endif




int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
    osip_t *osip;
    if(0 != osip_init(&osip)) {
        fprintf(stderr, "cannot init libosip2\n");
        exit(1);
    }

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  1000, &callback, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        printf("pkt received\n");
        nfq_handle_packet(h, buf, rv);
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}



/* 
 * 1.   copy ethernet packet from kernel to application
 * 2.   parse ethernet packet, get ip packet
 * 3.   parse ip packet, 分片重组,获取get udp/tcp整个包
 *      (don't handle tcp packet now, but must have access port)    
 * 4.   parse udp packet， get sip packet.
 */

/* 当内核数据拷贝到应用层时,回调函数被调用 */
static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
        struct nfq_data *nfa, void *data)
{
    u_int32_t id = parse_eth_pkt(nfa);
    printf("entering callback\n");
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}


/* returns packet id */
static u_int32_t parse_eth_pkt(struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi; 
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
                ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0)
        printf("payload_len=%d ", ret);

    fputc('\n', stdout);

    parse_ip_pkt();
    parse_tcp_pkt(); parse_udp_pkt();
    parse_app_pkt();

    return id;
}

/*
 * app_pkt: 完整的sip报文
 * len    : 报文长度
 */
int parse_app_pkt(unsigned char *app_pkt, int len)
{
    
}

int handle_sip_message(unsigned char *buff, int len_buff)
{
    /* 1. 检验sip包的完整性及正确性 */
    //security_check_raw()
    //security_check_sip()

    /* 2. 解析sip包 */
    osip_message_t *sip;
    if(0 != osiop_message_init(&sip)){
        fprintf(stderr, "cannot init osip_message_t\n");
        return -1;
    }

    if(0 != osip_message_parse(sip, buff, len_buff)) {
        fprintf(stderr, "cannot parse osip_message_t\n");
        exit(1);
    }

    if(MSG_IS_REQUEST(sip)) {
        handle_sip_request(sip);
    }
    else if(MSG_IS_RESPONSE(sip)) {
        handle_sip_response(sip);
    }
}


int handle_sip_request(osip_message_t *request)
{
    if(MSG_IS_INVITE(request)) {

    }
    else if(MSG_IS_ACK(request)) {

    }
    else if(MSG_IS_REGISTER(request)) {

    }
    else if(MSG_IS_BYE(request)) {

    }
    else if(MSG_IS_OPTIONS(request)) {

    }
    else if(MSG_IS_INFO(request)) {

    }
    else if(MSG_IS_CANCEL(request)) {

    }
    else if(MSG_IS_REFER(request)) {

    }
    else if(MSG_IS_NOTIFY(request)) {

    }
    else if(MSG_IS_SUBSCRIBE(request)) {

    }
    else if(MSG_IS_MESSAGE(request)) {

    }
    else if(MSG_IS_PRACK(request)) {

    }
    else if(MSG_IS_UPDATE(request)) {

    }
    else if(MSG_IS_PUBLISH(request)) {

    }
}

int handle_register(osip_message_t *request)
{
    /* 基本UAC信息: 用户名userID, 本地l_ip, 发起注册的l_port, 注册服务器的s_host, 监听端口s_port, CSeq_num, CSeq_method, Expires */
    /* 1. 注册消息 */
    char  userID[1024];
    char  l_ip[LEN_IP_STR];
    char  s_host[LEN_HOST];
    short l_port;
    short s_port;
    int   CSeq_num;
    char  CSeq_method[LEN_METHOD];
    char  expires[LEN_EXPIRES];

}


int handle_sip_response(osip_message_t *response)
{
    if(MSG_IS_STATUS_1XX(response)) {

    }
    else if(MSG_IS_STATUS_2XX(response)) {

    }
    else if(MSG_IS_STATUS_3XX(response)) {

    }
    else if(MSG_IS_STATUS_4XX(response)) {

    }
    else if(MSG_IS_STATUS_5XX(response)) {

    }
    else if(MSG_IS_STATUS_6XX(response)) {

    }

}


