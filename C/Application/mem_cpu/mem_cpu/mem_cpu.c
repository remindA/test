#include "mem_cpu.h"

//MEMUsedPerc=100*(MemTotal-MemFree-Buffers-Cached)/MemTotal.
//failure return:0(in no way used percentage of memory would be 0%)
//success return:percentage of used memory(float)
float get_mem_used_percent(void)
{
    s_mem_info info;
    memset(&info, 0, sizeof(info));
    if(get_mem_info(&info) <0)
        return 0.0;
    else
    {
        printf("used=%10u\n",info.mem_total - info.mem_free -info.mem_buffers - info.mem_caches);
        printf("total =%10u\n", info.mem_total);
        // do division first,then do mutiple.otherwise the number would be to big for computer.
        return 100*( ( float)(info.mem_total - info.mem_free -info.mem_buffers - info.mem_caches)/info.mem_total);
    }

}


//any failure return -1;
//only success return 0;
int get_mem_info(s_mem_info *mem_info)
{
    FILE *fp_mem = fopen("/proc/meminfo", "r");
    if(fp_mem == NULL)
    {
        perror("fopen /proc/meminfo");
        return -1;
    }

    char line_buf[LINE_MAX_NUM] = {0};
    unsigned long a_mem_info[NEEDED_LINE_NUM] = {0};
    int i = 0;
    for(i = 0; i < NEEDED_LINE_NUM; i++)
    {
        if(fgets(line_buf, LINE_MAX_NUM, fp_mem) != NULL)
        {
            //printf("%s", line_buf);
            a_mem_info[i] = get_num_from_str(line_buf);
        }
        else return -1;
    }
    mem_info->mem_total = a_mem_info[0];
    mem_info->mem_free = a_mem_info[1];
    mem_info->mem_available = a_mem_info[2];
    mem_info->mem_buffers = a_mem_info[3];
    mem_info->mem_caches = a_mem_info[4];
    fclose(fp_mem);
    return 0;
}


//abc:   123434 KB
//return 123434
unsigned long get_num_from_str(char *line_buf)
{
    unsigned long numbers = 0;
    sscanf(line_buf, "%*s %u %*s", &numbers);
    //printf("%u\n", numbers);
    /*
    char c_numbers[11] = {0};
    unsigned char num_len = 0;
    int i = 0;
    for(i=  0; i < strlen(line_buf) ; i++)
    {
        if(line_buf[i] >='0' && line_buf[i] <= '9')
        {
            c_numbers[num_len] = line_buf[i];
            num_len++;
        }
    }
    //printf("c_numbers=%s\n", c_numbers);
    char *end;
    numbers = strtoul(c_numbers, &end, 0);
    */
    return numbers;
}


//any failure return:-1(this would happen in no occuration)
//success return: percent of occupied of cpu(use the word "used" to describle cpu is not siutable)
float get_cpu_occupied_percent(void)
{
    s_cpu_info cpu_info_1, cpu_info_2;
    unsigned long cpu_total_diff = 0;
    unsigned long cpu_idle_diff = 0;
    int ret1, ret2;
    ret1 = get_cpu_info(&cpu_info_1) ;
    sleep(2);
    ret2 = get_cpu_info(&cpu_info_2) ;
    if(ret1 == 0 && ret2 == 0)
    {
        cpu_total_diff = cpu_info_2.cpu_total - cpu_info_1.cpu_total;
        cpu_idle_diff = cpu_info_2.cpu_idle - cpu_info_1.cpu_idle;
        printf("cpu_total_diff=%u\n", cpu_total_diff);
        printf("cpu_idle_diff=%u\n", cpu_idle_diff);
        // do division first,then do mutiple.otherwise the number would be to big for computer.
        return 100*((cpu_total_diff*1.0 - cpu_idle_diff)/cpu_total_diff);
    }
    else
        return -1;
}


int get_cpu_info(s_cpu_info *cpu_info)
{
    FILE *fp_cpu = fopen("/proc/stat", "r");
    if(fp_cpu ==   NULL)
    {
        perror("fopen /proc/stat");
        return -1;
    }

    char line_buf[LINE_MAX_NUM] = {0};
    int i = 0;

    //just need the first line
    if(fgets(line_buf, LINE_MAX_NUM, fp_cpu) == NULL)
    {
        perror("fgets the first line of /proc/stat");
        fclose(fp_cpu);
        return -1;
    }
    else{
        //printf("%s\n", line_buf);
        int ret = sscanf(line_buf, "%*s  %u %u %u %u %u %u %u %u %u %u", &cpu_info->cpu_user, &cpu_info->cpu_nice, &cpu_info->cpu_system, &cpu_info->cpu_idle, &cpu_info->cpu_iowait, &cpu_info->cpu_irq, &cpu_info->cpu_softirq, &cpu_info->cpu_stealstolen, &cpu_info->cpu_guest, &cpu_info->cpu_unknown);
        printf("cpu  %u %u %u %u %u %u %u %u %u %u\n",cpu_info->cpu_user, cpu_info->cpu_nice, cpu_info->cpu_system, cpu_info->cpu_idle, cpu_info->cpu_iowait,cpu_info->cpu_irq, cpu_info->cpu_softirq,cpu_info->cpu_stealstolen, cpu_info->cpu_guest, cpu_info->cpu_unknown);
        if(CPU_INFO_NUMBERS != ret)
        {
            fclose(fp_cpu);
            return -1;
        }
        else{
            cpu_info->cpu_total = cpu_info->cpu_user+cpu_info->cpu_nice+cpu_info->cpu_system+cpu_info->cpu_idle+cpu_info->cpu_iowait+cpu_info->cpu_irq+cpu_info->cpu_softirq+cpu_info->cpu_stealstolen+cpu_info->cpu_guest+cpu_info->cpu_unknown;
            //printf("cpu_total=%u\n", cpu_info->cpu_total);
            fclose(fp_cpu);
            return 0;
        }
    }
}
