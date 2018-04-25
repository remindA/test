#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

typedef unsigned char  tlv_type_t;
typedef unsigned short tlv_lenght_t;
typedef char           tlv_value_t;


//#pragma pack(1) is a must. or it will cause wrong information.
#pragma pack(1)
typedef struct
{
    tlv_type_t   type;
    tlv_lenght_t length;
    tlv_value_t  value[0];
}tlv_t;


int parse_tlv(unsigned short *len_data, unsigned char **data, tlv_t **tlv);
int main(int argc, char **argv)
{

    tlv_t *tlv_1, *tlv_2;
    tlv_lenght_t len = strlen("hello") + 1;
    tlv_1 = (tlv_t *)malloc(sizeof(tlv_t) + len);
    tlv_1->type = 1;
    tlv_1->length = len;
    memcpy(tlv_1->value, "hello", tlv_1->length);
    printf("tlv_1->value=%s\n", tlv_1->value);

    len = strlen("world") + 1;
    tlv_2 = (tlv_t *)malloc(sizeof(tlv_t) + len);
    tlv_2->type = 2;
    tlv_2->length = len;
    memcpy(tlv_2->value, "world", tlv_2->length);
    printf("tlv_2->value=%s\n", tlv_2->value);
    
    unsigned char *data = NULL;
    tlv_lenght_t len_data = 2*sizeof(tlv_t) + tlv_1->length + tlv_2->length;
    printf("data_len=%d\n", len_data);
    data = (unsigned char *)malloc(len_data);
    //printf("main data=%p\n", data);
    memcpy(data, tlv_1, sizeof(tlv_t) + tlv_1->length);
    memcpy(data + sizeof(tlv_t) + tlv_1->length, tlv_2, sizeof(tlv_2) + tlv_2->length);
    printf("data-value_1:%s\n", data + sizeof(tlv_t));
    printf("data-value_2:%s\n", data + sizeof(tlv_t) + tlv_1->length + sizeof(tlv_t));

    tlv_t *tlv_tmp = NULL;
    int ret = -1;
    while((ret = parse_tlv(&len_data, &data, &tlv_tmp) == 0))
    {
        //printf("after first parse_tlv *data=%p\n", data);
        //printf("15\n");
        printf("%d %d %s\n", tlv_tmp->type, tlv_tmp->length, tlv_tmp->value);
        //printf("16\n");
        free(tlv_tmp);
        //printf("17\n");
        tlv_tmp = NULL;
    }


    return 0;

}


int parse_tlv(unsigned short *len_data, unsigned char **data, tlv_t **tlv)
{
    tlv_type_t   type;
    tlv_lenght_t length;
    
    if(*len_data <= 0)
    {
        *data = NULL;
        return -1;
    }
    memcpy(&type, *data, sizeof(tlv_type_t));
    *len_data -= sizeof(tlv_type_t);
    *data += sizeof(tlv_type_t);

    memcpy(&length, *data, sizeof(tlv_lenght_t));
    *len_data -= sizeof(tlv_lenght_t);
    *data += sizeof(tlv_lenght_t);
    
    *tlv = (tlv_t *)malloc(sizeof(tlv_t) + length);
    if(NULL == tlv)
    {
        perror("malloc");
        return -1;    
    }
    (*tlv)->type = type;
    (*tlv)->length = length;
    memcpy((*tlv)->value, *data, (*tlv)->length);
    *len_data -= (*tlv)->length;
    *data += (*tlv)->length;

    return 0;
}
