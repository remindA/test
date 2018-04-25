#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int create(char **value)
{
	*value = (char *)malloc(100);
	if(NULL == *value)
		return -1;
	memset(*value, 0, 100);
	strcpy(*value, "hello");
	return 0;
}


int main()
{


	char *ptr = NULL;
	if(create(&ptr) == 0)
		printf("%s\n", ptr);
	free(ptr);


	char *data = (char *)malloc(100);
	if(data != NULL)
	{
		strcpy(data, "world");
		printf("%s\n", data);
	}
	return 0;
}
