#include "MAC.h"


int get_eth_MAC(char *eth_name, unsigned char *MAC)
{
	struct ifreq ifr;
	int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock_fd < 0)
	{
		perror("socket");
		return sock_fd;
	}
	strncpy(ifr.ifr_name,(char *)eth_name, sizeof(ifr.ifr_name) );

	int ret_ioctl = ioctl(sock_fd, SIOCGIFHWADDR, &ifr);
	if(ret_ioctl < 0)
	{
		perror("ioctl");
		return ret_ioctl;
	}

	int i = 0;
    	for(i = 0 ; i < 14; i++)
	{
		printf("%02x\t",(unsigned char)ifr.ifr_hwaddr.sa_data[i]);
	}
	printf("\n");
	memcpy(MAC, ifr.ifr_hwaddr.sa_data, 6);
	close(sock_fd);
	return 0;
}

int get_eth_IP(char *eth_name, unsigned char *IP)
{
	struct ifreq ifr;
	int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock_fd < 0)
	{
		perror("socket");
		return sock_fd;
	}
	strncpy(ifr.ifr_name,(char *)eth_name, sizeof(ifr.ifr_name) );

	int ret_ioctl = ioctl(sock_fd, SIOCGIFADDR, &ifr);
	if(ret_ioctl < 0)
	{
		perror("ioctl");
		return ret_ioctl;
	}
	int i = 0;
	for(i = 0; i < 14; i++)
	{
		printf("%d\t", (unsigned char)ifr.ifr_addr.sa_data[i]);
	}
	printf("\n");
	memcpy(IP, ifr.ifr_addr.sa_data+2, 4);
	close(sock_fd);
	return 0;
}


int get_eth_broadaddr(char *eth_name, unsigned char *broadaddr)
{

	struct ifreq ifr;
	int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock_fd < 0)
	{
		perror("socket");
		return sock_fd;
	}
	strncpy(ifr.ifr_name,(char *)eth_name, sizeof(ifr.ifr_name) );

	int ret_ioctl = ioctl(sock_fd, SIOCGIFBRDADDR, &ifr);
	if(ret_ioctl < 0)
	{
			perror("ioctl");
			return ret_ioctl;
	}
	int i = 0;
	for(i = 0; i < 14; i++)
	{
		printf("%d\t", (unsigned char)ifr.ifr_broadaddr.sa_data[i]);
	}
	printf("\n");
	memcpy(broadaddr, ifr.ifr_broadaddr.sa_data+2, 4);

	close(sock_fd);
	return 0;
}
