#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>


typedef struct{
    char keys[50];
}ajax_key_t;

ajax_key_t ajax_keys_tab[] = {
    {"niuyaben"},
    {"richard sugarman"}
};


typedef struct{
    char *pname;
}ipt_proto_t;


int main(int argc, char **argv)
{
    ipt_proto_t proto[] = {
        {"tcp"},
        {"udp"},
        {"icmp"},
        {NULL}
    };
    
    ipt_proto_t *p;
    for(p = proto; p->pname; p++) {
        printf("p->pname=%s\n", p->pname);
    }
    return 0;
}
