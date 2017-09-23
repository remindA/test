#include "http_rpl.h"

int parse_http_request_header(int c_fd, http_request_t *req)
{
    int n = 0;
    char line[LEN_LINE] = {0};
    if((n = read_line(c_fd, line, sizeof(line))) <= 0)
        return -1;
    #ifdef DEBUG
    printf("line=%s", line);
    #endif
    parse_http_req_line(line, req);
    memset(line, 0, sizeof(line));
    while((n = read_line(c_fd, line, sizeof(line))) > 0)
    {
        if(strcmp(line, "\r\n") != 0)
        {
            #ifdef DEBUG
            printf("line=%s", line);
            #endif
            http_field_t *field = (http_field_t *)malloc(sizeof(http_field_t));
            parse_http_filed(line, field);
            list_add_tail(&(field->list), &(req->head));
            memset(line, 0, sizeof(line));
        }
        else
            break;
    }
    return 0;
}

int parse_http_response_header(int s_fd, http_response_t *rsp)
{
    int n = 0;
    char line[LEN_LINE] = {0};
    if((n = read_line(s_fd, line, sizeof(line))) <= 0)
        return -1;
    #ifdef DEBUG
    printf("line=%s", line);
    #endif
    parse_http_rsp_line(line, rsp);
    memset(line, 0, sizeof(line));
    while((n = read_line(s_fd, line, sizeof(line))) > 0)
    {
        if(strcmp(line, "\r\n") != 0)
        {
            #ifdef DEBUG
            printf("line=%s", line);
            #endif
            http_field_t *field = (http_field_t *)malloc(sizeof(http_field_t));
            parse_http_filed(line, field);
            list_add_tail(&(field->list), &(rsp->head));
            memset(line, 0, sizeof(line));
        }
        else
            break;
    }
    return 0;
}

//缺陷版
int read_line(int fd, char *buff, int cnt)
{
    int  tot_read = 0;
    int  n = 0;
    char c = 0;
    while(1)
    {
        n = read(fd, &c, 1);
        if(n < 0)
        {
            if(errno == EINTR)
                continue;
            else
                return -1;
        }
        else if(n == 0)
        {
            break;
        }
        else
        {
            if(tot_read < cnt - 1)
            {
                tot_read++;
                *buff++ = c;
            }
            //一行超过最大缓存长度的部分就被阶段了
            //需要修改
        }
        if(c == '\n')
            break;
    }
    return tot_read;
}

void parse_http_req_line(const char *line, http_request_t *req_line)
{
    /* get /xxx/yyy/jjdw  HTTP/1.1 */
    char *format = "%s %s %s";
    sscanf(line, format, req_line->method, req_line->url, req_line->ver);
}

void parse_http_rsp_line(const char *line, http_response_t *rsp_line)
{
    /* HTTP/1.1 200 OK */
    char *format = "%s %s %s";
    sscanf(line, format, rsp_line->ver, rsp_line->stat_code, rsp_line->stat_info);
}


void parse_http_filed(const char *line, http_field_t *field)
{
    /* Host: 192.168.1.33 */
    /* Date: 2017.09.20 11:33:33 */
    char *format = "%[^:]:%*[ ]%[^'\n']";
    sscanf(line, format, field->key, field->value);
}


int get_server_ip_port(struct list_head *req_head, const char *s_ip, short *s_port)
{
    struct list_head *pos = NULL;
    list_for_each(pos, req_head)
    {
        http_field_t *field = list_entry(pos, http_field_t, list);
        if(strcasecmp(field->key, "Host") == 0)
        {
            char p1 = strchr(":");
            if(p1)
            {
                int offset = p1 - field->value;
                strncpy(s_ip, field->value, offset);
                char port[12] = {0};
                strncpy(port, p1 + 1, strlen(field->value) - offset);
                s_port = (short)atoi(port);   //aoti(" 123 ") also works well
            }
            else
            {
                strncpy(s_ip, field->value, offset);
                s_port = DEFAULT_SERVER_PORT;
            }
            return 0;
        }
    }
    return -1;
}

size_t get_response_priority(struct list_head *rsp_head, int *pr)
{
    size_t len = 0;
    int is_txt = 0;
    struct list_head *pos = NULL;
    list_for_each(pos, rsp_head)
    {
        http_field_t *field = list_entry(pos, http_field_t, list);
        if(strcasecmp("Content-type", field->key) == 0)
        {
            int i = 0;
            for(i = 0; i < sizeof(text_table)/sizeof(c_type_t); i++)
            {
                if(strncasecmp(field->value, text_table[i]) == 0)
                {
                    is_txt = 1;
                    break;
                }
            }
            if((*pr = is_txt?*pr:PR_NONE_TXT) == PR_NONE_TXT)
                break;
        }
        if(strcasecmp("Content-length", field->key) == 0)
        {
            *pr = (*pr == PR_CHUNKED)?*pr:PR_CONTENT_LEN;
            len = (size_t)aoti(field->value);
        }
        if(strcasecmp("Transfer-encoding", field->key) == 0 && strcasecmp("chunked", field->value))
            *pr = PR_CHUNKED;

    }
    return len;
}

