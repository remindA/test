#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define TYPE_STRING 0x01
#define TYPE_NUMBER 0x02
#pragma pack (1)
typedef struct tlv
{
	unsigned char type;
	int length;
	void value[0];
}tlv_t;

int main(int argc, char **argv)
{
    int age = 20;
    char *name = "richard";
    tlv_t *tlv = (tlv_t *)calloc(1, sizeof(tlv_t) + sizeof(int));
    if(NULL == tlv) {
        perror("calloc");
        return -1;
    }
    tlv->type = TYPE_NUMBER;
    tlv->
	return 0;
}
