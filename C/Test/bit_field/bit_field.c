/*
 * =====================================================================================
 *
 *       Filename:  bit_field.c
 *
 *    Description:  位域测试
 *
 *        Version:  1.0
 *        Created:  2018年07月27日 17时45分52秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

struct proto_head{
    unsigned int head: 16;
    unsigned int version: 16;
    unsigned int reserver: 8;
    unsigned int cmd: 16;
    unsigned int dlen: 16;
    unsigned int tail: 16;
};

int main()
{
    struct proto_head pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.head = 0x5555;
    pkt.version = 0x4010;
    pkt.reserver = 0x00;
    pkt.cmd = 0x1010;
    pkt.dlen = 0x0000;
    pkt.tail = 0x5444;
    printf("sizeof(pkt) = %d\n",sizeof(pkt));
    printf("head = 0x%04x, version=0x%04x, reserver=0x%02x, cmd=0x%04x, dlen=0x%04x, tail=0x%04x\n", 
            pkt.head, pkt.version, pkt.reserver, pkt.cmd, pkt.dlen, pkt.tail);

    return 0;
}

