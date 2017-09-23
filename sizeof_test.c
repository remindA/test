#include <stdio.h>

void sizeof_(char *buf)
{
	printf("sizeof(buf) = %d\n", sizeof(buf));
}

void sizeof_const(const char *buf)
{	
	printf("sizeof(buf) = %d\n", sizeof(buf));
}
int main()
{

	char ip[16] = "";
	printf("sizeof(ip) = %d\n", sizeof(ip));
	sizeof_(ip);
	sizeof_const(ip);
	sizeof_const("192.168");

	return 0;
}
