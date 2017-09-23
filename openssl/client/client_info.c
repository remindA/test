#include "client_info.h"

int get_client_info(s_client_info *client_info)
{
	memset(client_info, '\0', sizeof(s_client_info));
	char *ptr_ip;
	char *ptr_mac;
	char *ptr_cpu;
	char *ptr_disk;
	char *ptr_host_name;
	ptr_ip	= get_ip(EHT0_NAME, client_info->ip);
	ptr_mac = get_mac(EHT0_NAME, client_info->mac);
	ptr_cpu = get_cpu_info(client_info->cpu_info);
	ptr_disk = get_disk_info(client_info->disk_info);
	ptr_host_name = get_host_name(client_info->host_name);

	//利用mac,cpu,disk计算machine_code,所以不能全为空。
	if(NULL == ptr_mac && NULL == ptr_cpu && NULL == ptr_disk)
		return -1;
	if(NULL == ptr_cpu)
		strcpy(client_info->cpu_info, "none");
	if(NULL == ptr_disk)
		strcpy(client_info->disk_info, "none");
	memset(&(client_info->machine_code), '\0', sizeof(client_info->machine_code));
	produce_machine_code(client_info->machine_code, client_info->mac, client_info->cpu_info, client_info->disk_info);

	
	return 0;

}


int produce_machine_code(char *machine_code, const char *mac, const char *cpu, const char *disk)
{
	//利用openssl提供的加密算法计算machine_code。
	//暂时没有实现，直接组合mac, cpu, disk
	sprintf(machine_code, "%s+%s+%s", mac, cpu, disk);
	return 0;
}
