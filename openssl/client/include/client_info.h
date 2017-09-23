#ifndef _CLIENT_INFO_H_
#define _CLIENT_INFO_H_


#include <stdio.h>
#include <string.h>
#include "device_info.h"
#include "saa_include.h"

#define EHT0_NAME    "eth0"


extern int get_client_info(s_client_info *client_info);
extern int produce_machine_code(char *machine_code, const char *mac, const char *cpu, const char *disk);
#endif
