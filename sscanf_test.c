#include <stdio.h>


int main(int argc, char **argv)
{
	/*
	int  i_addr = 0;
	sscanf(argv[1], "%x", &i_addr);
	printf("i_addr=%d\n", i_addr);
	printf("i_addr=0x%x\n", i_addr);
	printf("i_addr<<4=0x%05x\n", i_addr<<4);
	printf("i_addr<<16=0x%08x\n", i_addr<<16);
	*/
    /*
	char string[512]  = "get /setup.cgi?ajax http/1.1";
	char string2[512] = "get   /setup.cgi?ajax   http/1.1";
	char *format = "%[^ ] %[^ ] %[^ ]";
	char *format2 = "%s %s %s";
	char method[32] = {0};
	char uri[32] = {0};
    char ver[32] = {0};
    */
    char string[512] = "Date: 2019.09.20 12:00:00";
    char string2[512] = "Date:   2019.09.20 12:00:00";
    char string3[512] = "Content-length: 19200";
    char *format = "%[^:]:%*[' ']%[^\r\n]";
    char key[32] = {0};
    char value[32] = {0};
	int ret = sscanf(string3, format, key, value);
	printf("ret=%d\n%s\n%s\n", ret, key, value);
    char *format3 = "%[^:]:%s";
    char *host = "192.168.1.33:80";
    char *host2 = "www.baidu.com:80";
    char hh[128];
    char port[10];
    sscanf(host, format3, hh, port);
    printf("%s %s\n", hh, port);
    sscanf(host2, format3, hh, port);
    printf("%s %s\n", hh, port);

    char remap[] = "0,192.168.1.1,5.5.5.5";
    char *frt = "%[^,],%[^,],%[^,]";
    char unknow[16] = {0};
    char before[16] = {0};
    char after[16] = {0};
    ret = sscanf(remap, frt, unknow, before, after);
    printf("ret=%d, before=%s, after=%s\n", ret, before, after);
    
    char *format4 = "%s %s %[^'\r''\n']";
    char *rsp1 = "HTTP/1.1 200 OK\r\n";
    char *rsp2 = "HTTP/1.1 400 BAD REQUEST\r\n";
    char ver[64];
    char stat[64];
    char info[64];
    sscanf(rsp1, format4, ver, stat, info);
    printf("[%s], [%s], [%s]\n", ver, stat, info);
    sscanf(rsp2, format4, ver, stat, info);
    printf("[%s], [%s], [%s]\n", ver, stat, info);

	return 0;
}
