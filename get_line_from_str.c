#include <stdio.h>
#include <string.h>

char *read_line_from_str(char *src, char *line);

int main()
{
    char src[] = "GET /setup.cgi?nextfile=saa.html HTTP/1.1\r\nHost: www.baidu.com\r\nContent-Type: text/html\r\n\r\n...\r\n<a href=\"www.baidu.com\">baidu.com</a>\r\n";
    char line_buff[1024] = {0};
    char *p = src;
    while((p -src) != strlen(src))
    {
        memset(line_buff, 0 , sizeof(line_buff));
        p = read_line_from_str(p, line_buff);
    }
    return 0;
}

char *read_line_from_str(char *src, char *line)
{
    if(!src)
        return NULL;
    int i = 0;
    for(i = 0; i < strlen(src); i++)
    {
        if(src[i] == '\n')
            break;
    }
    strncpy(line, src, i + 1);
    printf("%s", line);
    return (src + i + 1);
}
