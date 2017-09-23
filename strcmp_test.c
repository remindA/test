#include <stdio.h>
#include <string.h>


int main()
{
	char buf[] = "\r\n";
	printf("strcmp()=%d\n", strcmp("\n", buf) );

	return 0;
}
