#include "tlv.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
	tlv_t *tlv_ip, *tlv_mac, *tlv_all;
	char ip[]  = "192.168.1.111";
	char mac[] = "11:22:33:44:55:66";
	int len_ip = strlen(ip) + 1;
	tlv_ip = (tlv_t *)malloc(sizeof(tlv_t) + len_ip);
	tlv_ip->type = TYPE_IP;
	tlv_ip->length = len_ip;
	memcpy(tlv_ip->value, ip, sizeof(len_ip));

	int len_mac = strlen(mac) + 1;
	tlv_mac = (tlv_t *)malloc(sizeof(tlv_t) + len_mac);
	tlv_mac->type = TYPE_MAC;
	tlv_mac->length = len_mac;
	memcpy(tlv_mac->value, mac, sizeof(len_mac));

	int len_all = sizeof(*tlv_ip) + sizeof(tlv_mac) + len_ip + len_mac;
	tlv_all = (tlv_t *)malloc(sizeof(tlv_t) + len_all);
	tlv_all->type = TYPE_ALL;
	tlv_all->length = len_all;
	memcpy(tlv_all->value, tlv_ip, sizeof(*tlv_ip) + len_ip);
	return 0;
}
