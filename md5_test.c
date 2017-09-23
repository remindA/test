#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <openssl/md5.h>
#include "openssl/ssl.h"

int main(int argc, char **argv)
{
    MD5_CTX ctx;
    unsigned char *data = "123";
    unsigned char md[16] = {0};
    char buff[33] = {0};
    char tmp[3] = {0};
    int i = 0;
    MD5_Init(&ctx);
    MD5_Update(&ctx, data, strlen(data));
    MD5_Final(md, &ctx);
    for(i = 0; i < 16; i++)
    {
        sprintf(tmp, "%02X", md[i]);
        strcat(buff, tmp);
    }
    printf("%s\n", buff);
        
    return 0;
}

