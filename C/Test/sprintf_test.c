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
    

    char buff[100] = {0};
    sprintf(buff, "%s", "GET");
    sprintf(buff, "%s %s", buff, "/");
    sprintf(buff, "%s %s\r\n", buff, "HTTP/1.1");
    printf("[%s]\n", buff);

    char *com = "this is my city";
    char comm[123] = {0};
    sprintf(comm, "%.*s", 5, com);
    printf("%s\n", comm);
	return 0;
}
