/*
 * =====================================================================================
 *
 *       Filename:  md5.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年07月17日 17时58分12秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/md5.h>
#define MD5_ONE

int main(int argc, char **argv)
{
    if(argc != 2) {
        printf("Usage: %s string\n", argv[0]);
        return 0;
    }
    
    unsigned char md5[MD5_DIGEST_LENGTH];

#ifdef MD5_ONE
    if(NULL == MD5(argv[1], strlen(argv[1]), md5)) {
        printf("Cannot MD5()\n");
        return 0;
    }
#else
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, argv[1], strlen(argv[1]));
    MD5_Final(md5, &ctx);
#endif

    int i;
    printf("md5 length = %d\n", MD5_DIGEST_LENGTH);
    for(i = 0; i < MD5_DIGEST_LENGTH; i++) {
        printf("%02x ", md5[i]);
    }
    printf("\n");

    return 0;
}




