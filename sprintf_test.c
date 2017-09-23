#include <stdio.h>
#include <string.h>

int main()
{
	char url[] = "/url?wkmwec=3&jnc=4";
	char *p_url = url;
	char path[512] = {0};
	printf("strlen(url)=%d,%s\n", strlen(url), url);

	while(*p_url != '?')
		p_url++;
	*p_url = '\0';
	sprintf(path,"%s", url);
	printf("strlen(url)=%d,%s\n", strlen(url), url);
	printf("strlen(path)=%d,%s\n", strlen(path), path);
	return 0;
}
