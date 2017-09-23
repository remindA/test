#ifndef _DEVICE_INFO_H_
#define _DEVICE_INFO_H_

#include "if_info.h"

extern char *get_ip(const char *if_name, char *ip);
extern char *get_mac(const char *if_name, char *mac);
extern char *get_cpu_info(char *cpu);
extern char *get_disk_info(char *disk);
extern char *get_host_name(char *host_name);

#endif

