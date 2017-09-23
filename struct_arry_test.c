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

int main(int argc, char **argv)
{

    int i = 0;
    int lenght = sizeof(ajax_keys_tab)/sizeof(ajax_key_t);
    for(i = 0; i < lenght; i++)
        printf("%s\n", ajax_keys_tab[i].keys);
        
    return 0;
}
