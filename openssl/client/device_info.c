#include "device_info.h"

char *get_ip(const char *if_name, char *ip)
{
	unsigned char if_ip[4];
	if(0 == get_eth_IP(if_name, if_ip))
	{
		sprintf(ip, "%d.%d.%d.%d", if_ip[0], if_ip[1], if_ip[2], if_ip[3]);
		return ip;
	}
	else
		return NULL;
}


char *get_mac(const char *if_name, char *mac)
{
	unsigned char if_mac[6];
	if(0 == get_eth_MAC(if_name, if_mac))
	{
		sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x", if_mac[0], if_mac[1], if_mac[2], if_mac[3], if_mac[4], if_mac[5]);
		return mac;
	}
	else
		return NULL;
}




/*
unsigned int veax;
unsigned int vebx;
unsigned int vedx;
unsigned int vecx;
 
void cpuid(unsigned int veax1)
{
	    asm("cpuid"
				:"=a"(veax),
				"=b"(vebx),
				"=c"(vecx),
				"=d"(vedx)
				:"a"(veax));
}
void LM(int var,uint32_t *vx)
{
	int i;
	for(i=0;i<3;i++)
	{
		var=(var>>i);
		vx[i]=var;
	}
}
  
static void getcpuid (char *id)
{
	uint32_t ax[3],cx[3],dx[3];
	cpuid(1);
	LM(veax,ax);
	cpuid(3);
	LM(vecx,cx);
	LM(vedx,dx);
	sprintf(id,"%u%u%u%u%u%u%u%u%u",ax[0],ax[1],ax[2],cx[0],cx[1],cx[2],dx[0],dx[1],dx[2]);
}
  
int main(void)
{
	char cpuid[100];
	getcpuid(cpuid);
	printf("cpuid is %s\n",cpuid);
	return 0;
}
*/

char *get_cpu_info(char *cpu_id)
{
	return NULL;
}

char *get_disk_info(char *disk)
{
	return NULL;
}

char *get_host_name(char *host_name)
{
	char cmd[128] = "hostname";		//输出hostname,只有一行。
	FILE *fp = popen(cmd, "r");
	if(NULL == fp)
	{
		perror("popen");
		return NULL;
	}
	if(!fgets(host_name, sizeof(host_name), fp))
		return NULL;
	
	int i = 0;
	for(i = 0; i < strlen(host_name); i++)
		host_name[i] = host_name[i]=='\n'?'\0':host_name[i];

	pclose(fp);
	return host_name;
}
