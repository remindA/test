#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <math.h>
#include <string.h>

int dec2hex(unsigned int dec, char *hex)
{
    return sprintf(hex, "%x", dec);
}


int hex2dec(char *hex, unsigned int *dec)
{
    int i = 0;
    *dec  = 0;
    int power;
    int max_power = strlen(hex);
    for(i = 0; i < max_power; i++)
    {
        int truth;
        printf("hex[%d]=%c\n", i, hex[i]);
        if(hex[i] >= '0' && hex[i] <= '9')
            truth = hex[i] - '0';
        else if(hex[i] >= 'a' && hex[i] <= 'f')
            truth = hex[i] - 'a' + 10;
        else if(hex[i] >= 'A' && hex[i] <= 'F')
            truth = hex[i] - 'A' + 10;
        else 
            return -1;
        power = max_power - i - 1;
        printf("truth=%d, power=%d\n", truth, power);
        *dec += (unsigned int)(truth*pow(16, power));
    }
    return 0;
}


int main(int argc, char **argv)
{
    unsigned int dec = 65535;
    //char hex[33] = "FFFF";
    //dec2hex(dec, hex);
    hex2dec(argv[1], &dec);
    printf("%d ==> 0x%s\n", dec, argv[1]);
    return 0;
}
