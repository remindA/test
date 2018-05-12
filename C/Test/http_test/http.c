#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int parse_http_header(const char *buf)

int parse_http_header(const char *buf)
{
    if(buf == NULL) {
        return -1;
    }
    char *line;
    char *start;
    char *crlf;
    start = buf;
    line  = buf;
    int ret;
    if(crlf = strstr(line, "\n")) {
        *crlf = '\0';
        printf("%s\n", line);
        char str[LEN_METHOD + LEN_VER] = {0};
        char mid[LEN_URL + LEN_STAT_CODE] = {0};
        char end[LEN_VER + LEN_STAT_INFO] = {0};
        char *format = "%s %s %[^'\n']";
        ret = sscanf(line, format, str, mid, end);
        if(ret != 3) {
            printf("parse_http_header: message line ret = %d != 3\n", ret);
            return -1;
        }
        if(atoi(mid) > 0) {
            strcpy(header->ver, str);
            strcpy(header->stat_code, mid);
            strcpy(header->stat_info, end);
        }
        else {
            strcpy(header->method, str);
            strcpy(header->url, mid);
            strcpy(header->ver, end);
        }
        line = crlf + 1;
    }
    while((crlf = strstr(line, "\n"))) {
        *crlf = '\0';
        printf("%s\n", line);
        http_field_t *field = (http_field_t *)malloc(sizeof(http_field_t));
        if(parse_http_field(line, field) < 0) {
            printf("cannot parse_http_line[%s]", line);
        }
        else {
            list_add_tail(&(field->list), &(header->head)); 
        }
        line = crlf + 1;
    }
    printf("==========finish parse_http_header()==========\n");
    return 0;
}

int parse_http_field(const char *line)
{
    /* Host: 192.168.1.33 */
    /* Date: 2017.09.20 11:33:33 */
    int ret;
    char *p = strchr(line, ':');
    if(NULL == p) {
        return -1;
    }
    *p = '\0';
    strcpy(field->key, line);
    strcpy(field->value, p + 1);
    return 0;
}

