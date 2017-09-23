#include <stdio.h>
#include <string.h>
#include "saa_include.h"


int main(int argc, char **argv)
{

    s_element ele;
    memset(&ele, 0, sizeof(s_element));
    printf("ip=%s|\n", ele.client_info.ip);
    printf("mac=%s|\n", ele.client_info.mac);
    printf("cpu_info=%s|\n", ele.client_info.cpu_info);
    printf("disk_info=%s|\n", ele.client_info.disk_info);
    printf("host_name=%s|\n", ele.client_info.host_name);
    printf("machine_code=%s|\n", ele.client_info.machine_code);
    printf("auth_state=%s|\n", ele.auth_state);
    printf("addr_list=%s|\n", ele.addr_list);

    return 0;

}
