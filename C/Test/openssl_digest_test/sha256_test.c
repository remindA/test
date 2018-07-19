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
#include <openssl/sha.h>

int main(int argc, char **argv)
{
    if(argc != 2) {
        printf("Usage: %s string\n", argv[0]);
        return 0;
    }
    
    unsigned char sha256[SHA256_DIGEST_LENGTH];

    if(NULL == SHA256(argv[1], strlen(argv[1]), sha256)) {
        printf("Cannot SHA256()\n");
        return 0;
    }

    int i;
    printf("sha256 length = %d\n", SHA256_DIGEST_LENGTH);
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x ", sha256[i]);
    }
    printf("\n");

    return 0;
}




