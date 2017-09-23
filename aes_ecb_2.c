/* 
 * openssl为用户提供了丰富的指令，同时也提供了供编程调用的API，
 * 本文以使用128位aes算法的ecb模式进行加密和解密验证，如下所示
 * 第二种方法，使用EVP框架，示例如下
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

int main(void)
{
    char userkey[EVP_MAX_KEY_LENGTH];
    char iv[EVP_MAX_IV_LENGTH];
    unsigned char *date = malloc(AES_BLOCK_SIZE*3);
    unsigned char *encrypt = malloc(AES_BLOCK_SIZE*6);
    unsigned char *plain = malloc(AES_BLOCK_SIZE*6);
    EVP_CIPHER_CTX ctx;
    int ret;
    int tlen = 0;
    int mlen = 0;
    int flen = 0;

    memset((void*)userkey, 'k', EVP_MAX_KEY_LENGTH);
    memset((void*)iv, 'i', EVP_MAX_IV_LENGTH);
    memset((void*)date, 'p', AES_BLOCK_SIZE*3);
    memset((void*)encrypt, 0, AES_BLOCK_SIZE*6);
    memset((void*)plain, 0, AES_BLOCK_SIZE*6);

    /*初始化ctx*/
    EVP_CIPHER_CTX_init(&ctx);

    /*指定加密算法及key和iv(此处IV没有用)*/
    ret = EVP_EncryptInit_ex(&ctx, EVP_aes_128_ecb(), NULL, userkey, iv);
    if(ret != 1) {
        printf("EVP_EncryptInit_ex failed\n");
        exit(-1);
    }
    
    /*禁用padding功能*/
    EVP_CIPHER_CTX_set_padding(&ctx, 0);
    /*进行加密操作*/
    ret = EVP_EncryptUpdate(&ctx, encrypt, &mlen, date, AES_BLOCK_SIZE*3);
    if(ret != 1) {
        printf("EVP_EncryptUpdate failed\n");
        exit(-1);
    }
    /*结束加密操作*/
    ret = EVP_EncryptFinal_ex(&ctx, encrypt+mlen, &flen);
    if(ret != 1) {
        printf("EVP_EncryptFinal_ex failed\n");
        exit(-1);
    }

    tlen = mlen + flen;

    tlen = 0;
    mlen = 0;
    flen = 0;

    EVP_CIPHER_CTX_cleanup(&ctx);
    EVP_CIPHER_CTX_init(&ctx);
     
    ret = EVP_DecryptInit_ex(&ctx, EVP_aes_128_ecb(), NULL, userkey, iv);
    if(ret != 1) {
        printf("EVP_DecryptInit_ex failed\n");
        exit(-1);
    }
    
    EVP_CIPHER_CTX_set_padding(&ctx, 0);
    ret = EVP_DecryptUpdate(&ctx, plain, &mlen, encrypt, AES_BLOCK_SIZE*3);
    if(ret != 1) {
        printf("EVP_DecryptUpdate failed\n");
        exit(-1);
    }

    ret = EVP_DecryptFinal_ex(&ctx, plain+mlen, &flen);
    if(ret != 1) {
        printf("EVP_DecryptFinal_ex failed\n");
        exit(-1);
    }

    /*对比解密后与原数据是否一致*/
    if(!memcmp(plain, date, AES_BLOCK_SIZE*3)) {
        printf("test success\n");    
    } else {
        printf("test failed\n");    
    }

    printf("encrypt: ");
    int i;
    for(i = 0; i < AES_BLOCK_SIZE*3+4; i ++){
        printf("%.2x ", encrypt[i]);    
        if((i+1)%32 == 0){
            printf("\n");
        }
    }
    printf("\n");

    return 0;
}