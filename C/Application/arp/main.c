/*
 * main.c
 *
 *  Created on: 2017年6月9日
 *      Author: ben
 */


#include "MAC.h"
#include <errno.h>

typedef struct
{
    //DLC HEADER
    unsigned char dlc_dst_mac[6];
    unsigned char dlc_src_mac[6];
    unsigned short dlc_frame;

    //ARP PACKET
    unsigned short arp_hwtype;
    unsigned short arp_protype;
    unsigned char   arp_hwlen;
    unsigned char   arp_prolen;
    unsigned short arp_op;
    unsigned char arp_sender_mac[6];
    unsigned char arp_sender_ip[4];
    unsigned char arp_target_mac[6];
    unsigned char arp_target_ip[4];
    unsigned char padding[18];
}arp_packet;


int main(int argc, char **argv)
{

	//printf("sizeof(arp_packet)=%d\n", sizeof(arp_packet));
    //fill ARP packet
    struct sockaddr_ll sa_ll;
    printf("len of sockaddr_ll=%d\n", sizeof(struct sockaddr_ll) );
    bzero(&sa_ll, sizeof(sa_ll) );
    sa_ll.sll_family = PF_PACKET;
    sa_ll.sll_ifindex = if_nametoindex("eth0");

     int sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP) );
     if(sockfd < 0)
     {
            perror("socket");
            return 0;
     }
     printf("sockfd=%d\n", sockfd);

    arp_packet arp_pck;
    unsigned char brd_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    unsigned char dst_ip[4] = {192,168,1,111};
    unsigned char local_mac[6] = {0};
    unsigned char local_ip[4] = {0};
    get_eth_MAC("eth0", local_mac);
    get_eth_IP("eth0", local_ip);
    memcpy(arp_pck.dlc_src_mac, local_mac, 6);
    memcpy(arp_pck.dlc_dst_mac, brd_mac, 6);
    arp_pck.dlc_frame = htons(ETH_P_ARP);
    arp_pck.arp_hwtype = htons(0x0001);
    arp_pck.arp_protype = htons(ETH_P_IP);
    arp_pck.arp_hwlen  = 6;
    arp_pck.arp_prolen = 4;
    arp_pck.arp_op = htons(0x0001);
    memcpy(arp_pck.arp_sender_mac, local_mac, 6);
    memcpy(arp_pck.arp_sender_ip, local_ip, 4);
    memcpy(arp_pck.arp_target_mac, brd_mac, 6);
    memcpy(arp_pck.arp_target_ip, dst_ip, 4);
    bzero(arp_pck.padding, 18);



    int i = 0;
    for(i = 0; i < 256; i++)
    {
            dst_ip[3] = i;
            memcpy(arp_pck.arp_target_ip, dst_ip, 4);
            int ret = sendto(sockfd, &arp_pck, sizeof(arp_pck), 0, (struct sockaddr *)&sa_ll, sizeof(sa_ll) );
            if(ret > 0)
            {
                    //perror("sendto");
                    printf("arp request to %d.%d.%d.%d\n", dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]);
            }
    }

    while(1)
    {
    	bzero(&arp_pck, sizeof(arp_pck) );
    	ssize_t rcv_ret = recv(sockfd, &arp_pck, sizeof(arp_pck), 0);
    	if(rcv_ret > 0 && ntohs(arp_pck.arp_op) == 2)
    	{
    		int i = 0;
    		printf("opr=%u\n", ntohs(arp_pck.arp_op) );
    		printf("sender ip=");
    		for(i = 0; i < 4; i++)
    			printf("%d.", arp_pck.arp_sender_ip[i]);
    		printf("\n");

    		printf("sender mac=");
    		for(i = 0; i < 6 ; i++)
    				printf("%02x:",arp_pck.arp_sender_mac[i]);
    		printf("\n");

    		 printf("target ip=");
    		 for(i = 0; i < 4; i++)
    		    	printf("%d.", arp_pck.arp_target_ip[i]);
    		 printf("\n");

    		 printf("target mac=");
    		    	for(i = 0; i < 6 ; i++)
    		    			printf("%02x:",arp_pck.arp_target_mac[i]);
    		 printf("\n");


    		 char new_arp[256] = {0};
    		 char new_arp_ip[16] = {0};
    		 char new_arp_mac[18] = {0};
    		 //printf("after dingyi\n");
    		 sprintf(new_arp_ip, "%d.%d.%d.%d", arp_pck.arp_sender_ip[0], arp_pck.arp_sender_ip[1], arp_pck.arp_sender_ip[2], arp_pck.arp_sender_ip[3]);
    		 //printf("new_arp_ip=%s\n", new_arp_ip);
    		 sprintf(new_arp_mac, "%02x:%02x:%02x:%02x:%02x:%02x", arp_pck.arp_sender_mac[0], arp_pck.arp_sender_mac[1], arp_pck.arp_sender_mac[2], arp_pck.arp_sender_mac[3], arp_pck.arp_sender_mac[4],arp_pck.arp_sender_mac[5] );

    		 sprintf(new_arp, "arp -s %s %s", new_arp_ip, new_arp_mac);
    		 printf("%s\n", new_arp);
    	}
    }

    close(sockfd);
    return 0;
}




