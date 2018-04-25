#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
	char cmd[128] = "hostname";
	char buf[128] = {0};
	FILE *fp = popen(cmd, "r");
	if(fp == NULL)
	{
		perror("popen");
		exit(1);
	}
	fgets(buf, sizeof(buf), fp);
	int i = 0;
	for(i = 0; i < strlen(buf); i++)
	{
		buf[i] = buf[i]=='\n'?'\0':buf[i];
	}
	printf("%s\n", buf);
	
	pclose(fp);
	return 0;
}
