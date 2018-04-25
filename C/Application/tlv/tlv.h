#ifndef _TLV_H_
#define _TLV_H_

#pragma pack (1)
typedef struct tlv
{
	unsigned char type;
	int length;
	char value[0];
}tlv_t;

tlv_t arry
#define TYPE_ALL	0
#define TYPE_IP		1
#define TYPE_MAC	2



#endif
