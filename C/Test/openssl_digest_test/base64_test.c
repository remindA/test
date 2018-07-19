/*
 * =====================================================================================
 *
 *       Filename:  base64_test.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年07月18日 18时47分06秒
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
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

int main(int argc, char **argv)
{
    if(argc != 2) {
        printf("Usage: %s string\n", argv[0]);
        return 0;
    }
    BIO *b64;
    BIO *mem;
    BUF_MEM *ptr = NULL;
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    mem = BIO_new(BIO_s_mem());
    BIO_push(b64, mem);
    BIO_write(b64, argv[1], strlen(argv[1]));
    BIO_flush(b64);
    
    BIO_get_mem_ptr(b64, &ptr);
    char *buff = (char *)calloc(1, ptr->length+1);
    memcpy(buff, ptr->data, ptr->length);

    printf("%s\n", buff);

    free(buff);
    BUF_MEM_free(ptr);
    BIO_free(b64);
    BIO_free(mem);

    return 0;
}



