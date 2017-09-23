/* 
 * openssl为用户提供了丰富的指令，同时也提供了供编程调用的API，
 * 本文以使用128位aes算法的ecb模式进行加密和解密验证，如下所示
 * 第一种方法，直接使用aes算法提供的api进行调用，代码如下
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/aes.h>

int main(void)
{
    char userkey[AES_BLOCK_SIZE];
    unsigned char *date = malloc(AES_BLOCK_SIZE*3);
    unsigned char *encrypt = malloc(AES_BLOCK_SIZE*3 + 4);
    unsigned char *plain = malloc(AES_BLOCK_SIZE*3);
    AES_KEY key;

    memset((void*)userkey, 'k', AES_BLOCK_SIZE);
    memset((void*)date, 'p', AES_BLOCK_SIZE*3);
    memset((void*)encrypt, 0, AES_BLOCK_SIZE*6);
    memset((void*)plain, 0, AES_BLOCK_SIZE*3);

    /*设置加密key及密钥长度*/
    AES_set_encrypt_key(userkey, AES_BLOCK_SIZE*8, &key);

    int len = 0;
    /*循环加密，每次只能加密AES_BLOCK_SIZE长度的数据*/
while(len < AES_BLOCK_SIZE*3) {
        AES_encrypt(date+len, encrypt+len, &key);    
        len += AES_BLOCK_SIZE;
    }

    /*设置解密key及密钥长度*/    
    AES_set_decrypt_key(userkey, AES_BLOCK_SIZE*8, &key);

    len = 0;
    /*循环解密*/
while(len < AES_BLOCK_SIZE*3) {
        AES_decrypt(encrypt+len, plain+len, &key);    
        len += AES_BLOCK_SIZE;
    }

    /*解密后与原数据是否一致*/
    if(!memcmp(plain, date, AES_BLOCK_SIZE*3)){
        printf("test success\n");    
    }else{
        printf("test failed\n");    
    }

    printf("encrypt: ");
    int i = 0;
    for(i = 0; i < AES_BLOCK_SIZE*3 + 4; i++){
        printf("%.2x ", encrypt[i]);
        if((i+1) % 32 == 0){
            printf("\n");    
        }
    }
    printf("\n");    

    return 0;
}