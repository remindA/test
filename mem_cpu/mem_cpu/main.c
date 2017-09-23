#include "mem_cpu.h"
int main()
{
    while(1)
    {
        //printf("%.2f\n", get_mem_used_percent());
        printf("%.2f\n", get_cpu_occupied_percent());
        printf("\n");
        //sleep(1);
    }

    return 0;
}
