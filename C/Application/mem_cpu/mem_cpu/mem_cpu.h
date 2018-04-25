#ifndef _MEM_CPU_H
#define _MEM_CPU_H

#include <stdio.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

#define LINE_MAX_NUM    100
#define NEEDED_LINE_NUM 5
typedef struct {
    unsigned long mem_total;
    unsigned long mem_free;
    unsigned long mem_available;
    unsigned long mem_buffers;
    unsigned long mem_caches;
}s_mem_info;


#define CPU_INFO_NUMBERS 10
typedef struct{
    unsigned long cpu_total;
    unsigned long cpu_user;
    unsigned long cpu_nice;
    unsigned long cpu_system;
    unsigned long cpu_idle;
    unsigned long cpu_iowait;
    unsigned long cpu_irq;
    unsigned long cpu_softirq;
    unsigned long cpu_stealstolen;
    unsigned long cpu_guest;
    unsigned long cpu_unknown;
}s_cpu_info;

extern float get_mem_used_percent(void);
extern int get_mem_info(s_mem_info *mem_info);
unsigned long get_num_from_str(char *line_buf);

extern float get_cpu_occupied_percent(void);
extern int get_cpu_info(s_cpu_info *cpu_info);
#endif // _MEM_CPU_H
