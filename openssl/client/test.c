#include "client_info.h"

int main(int argc, char **argv)
{

	s_client_info client_info;
	int ret = get_client_info(&client_info);
	if(ret < 0)
	{
		printf("获取client_info失败\n");
		exit(1);
	}
	else
	{
		printf("ip = %s\n", client_info.ip);
		printf("mac = %s\n", client_info.mac);
		printf("cpu_info = %s\n", client_info.cpu_info);
		printf("disk_info = %s\n", client_info.disk_info);
		printf("host_name = %s\n", client_info.host_name);
		printf("machine_code = %s\n", client_info.machine_code);
		printf("ap = %s\n", client_info.ap);
	}
	
	return 0;
}
