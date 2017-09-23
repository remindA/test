#include <stdio.h>
#include <string.h>

int main()
{

    char *p = "wkojdw";
    char *p2 = NULL;
    char a[100] = "qdw";
    printf("p=%p, value=%s\n", p, p);
    printf("p2=%p, value=%s\n", p2, p2);
//    strcat(a, p2); strcat strlen等不可以传入null;
    strcat(a, NULL); 
    printf("a=%s\n", a);
    return 0;
}
