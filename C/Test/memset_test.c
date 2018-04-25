#include <string.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    char str[] = "http://192.168.1.33/setup.cgi?nextfile=remap.html";
    char arr[1024] = {0};
    char *p = strstr(str, "http://");
    if(p)
    {
        char *p1 = strchr(p + 7, '/');
        int end = strlen(p1);
        memmove(str, p1, strlen(p1));
        str[end] = 0;
        sprintf(arr, "%s", str);
        printf("%s\n", arr);
    }
    return 0;
}

