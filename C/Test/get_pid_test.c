#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>


int get_pid_from_ps(const char *process_name);
int main()
{
    char process[] = "bash";
    int pid = get_pid_from_ps(process); 
    printf("pid of %s = %d\n", process, pid);
    return 0;
}

int get_pid_from_ps(const char *process_name)
{
    char cmd[128] = {0};
    sprintf(cmd, "ps | grep \"%s\"", process_name);
    FILE *fp_ps = popen(cmd, "r");
    if(NULL == fp_ps)
    {
        perror("popen");
        return -1;
    }

    char line[256] = {0};
    if(NULL == fgets(line, sizeof(line), fp_ps))
    {
        perror("fgets");
        return -1;
    }
    char format[] = " %s ";
    char pid_str[6] = {0};
    sscanf(line, format, pid_str);
    printf("%s\n", line);
    printf("pid_str=%s\n", pid_str);
    
    pclose(fp_ps);
    return atoi(pid_str);
}
