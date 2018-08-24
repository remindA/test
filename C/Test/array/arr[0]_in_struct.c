#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma pack (1)
typedef struct tlv
{
	unsigned char type;
	int length;
	char value[0];
}tlv_t;

int main(int argc, char **argv)
{
	tlv_t *tlv_1;
	char data[] = "this is a test program !";
	int length = strlen(data) + 1;
	tlv_1 = (tlv_t *)malloc(sizeof(tlv_t) + length);
	tlv_1->type = 0x01;
	tlv_1->length = length;
	strcpy(tlv_1->value, data);
	printf("tlv_t length=%d\n", sizeof(tlv_t));
	printf("*tlv_1 length=%d\n", sizeof(*tlv_1));
	printf("tlv_1 type   = %02x\n", tlv_1->type);
	printf("tlv_1 length = %d\n", tlv_1->length);
	printf("tlv_1 value  = %s\n", tlv_1->value);
	free(tlv_1);

	return 0;
}
