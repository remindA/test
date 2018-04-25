#include <stdio.h>
#include <string.h>


int main(int argc, char **argv)
{
    char a[][5]={
        "niu",
        "ben",
        "dsv",
        "sjkcd",
        "wsdc"};
    int i = 0;
    for(i = 0; i < 5; i++)
    {
        printf("%s\n", *(a+i));
    }

    return 0;
}
