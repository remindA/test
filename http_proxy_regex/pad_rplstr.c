#include "pad_rplstr.h"



//typedef void (*pad_rplstr_t)(node_substr_t *node, void *table, size_t len);
/*
void pad_remap_rplstr_malloc(node_substr_t *node, void *remap_tab, size_t len)
{
    remap_t *remap_table = (remap_t *)remap_tab;
    int i = 0;
    for(i = 0; i < len; i++)
    {
        if(*(remap_table[i].before) != 0 && (strncmp(node->substr, remap_table[i].before, node->len_substr) == 0))
        {
            int len_rplstr = strlen(remap_table[i].after);
            node->rplstr = (char *)malloc(len_rplstr + 1);
            if(NULL == node->rplstr)
                perror("malloc node->rplstr");
            else
            {
                memset(node->rplstr, 0, len_rplstr + 1);
                memcpy(node->rplstr, remap_table[i].after, len_rplstr);
            }
        }
    }
}
*/

//typedef void (*pad_rplstr_t)(node_substr_t *node, struct list_head *head_table);
//这个函数将要取代上面的函数
void pad_list_rplstr_remap_table_req_m(node_substr_t *node, struct list_head *head_table)
{
    struct list_head *pos;
    list_for_each(pos, head_table)
    {
        remap_entry_t *entry = list_entry(pos, remap_entry_t, list);
        if(strcmp(node->substr, entry->after) == 0)
        {
#ifdef PADDEBUG
        printf("node->substr=%s, entry->before=%s\n", node->substr, entry->after);
#endif
            int len_rpl = strlen(entry->before);
            node->rplstr = (char *)malloc(len_rpl + 1);
            if(NULL == node->rplstr)
                perror("malloc");
            else
            {
                memset(node->rplstr, 0, len_rpl + 1);
                memcpy(node->rplstr, entry->before, len_rpl);
            }
        }
    }
}

void pad_list_rplstr_remap_table_rsp_m(node_substr_t *node, struct list_head *head_table)
{
    struct list_head *pos;
    list_for_each(pos, head_table)
    {
        remap_entry_t *entry = list_entry(pos, remap_entry_t, list);
        if(strcmp(node->substr, entry->before) == 0)
        {
#ifdef PADDEBUG
        printf("node->substr=%s, entry->before=%s\n", node->substr, entry->before);
#endif
            int len_rpl = strlen(entry->after);
            node->rplstr = (char *)malloc(len_rpl + 1);
            if(NULL == node->rplstr)
                perror("malloc");
            else
            {
                memset(node->rplstr, 0, len_rpl + 1);
                memcpy(node->rplstr, entry->after, len_rpl);
            }
        }
    }
}


//struct list_head *remap_table_head = get_remap_table_malloc();
/*
struct list_head *get_remap_table_m(void)
{
    //创建head,并初始化
    struct list_head *head = (struct list_head *)malloc(sizeof(struct list_head));
    if(NULL == head)
    {
        perror("malloc");
        return head;
    }
    init_list_head(head);

    //从nvram中读取信息
    int ret = scfgmgr_getall(&nvram_data);
    if(ret < 0 || NULL == nvram_data)
    {
        printf("get nvram failed, ret=%d\n");
        SAFE_FREE(head);
        return NULL;
    }
    char *remap = value_parser("ipmaps");
#ifdef PADDEBUG
    printf("ipmaps=%s\n", remap);
#endif
    int i = 0; 
    int cnt = 0;
    for(i = 0; i < strlen(remap); i++)
    {
        if(remap[i] == ';')
            cnt++;
    }
    //分割，取出，添加到链表remap_table
    printf("cnt=%d\n", cnt);
    char *str, *token;
    char *saveptr;
    for(i = 1, str = remap; ; i++, str = NULL)
    {
        token = strtok_r(str, ";", &saveptr);
        if(NULL == token && i == cnt+1)
        {
            printf("strtok_r ends\n");
            break;
        }
        remap_entry_t *entry = (remap_entry_t *)malloc(sizeof(remap_entry_t));
        if(NULL == entry)
        {
            perror("malloc");
            SAFE_FREE(head);
            return NULL;
        }
        memset(entry->before, 0, LEN_IP);
        memset(entry->after,  0, LEN_IP);
        char *format = "%[^,],%[^,],%[^,]";
        char direction[16] = {0};
        printf("token=%s\n", token);
        int n = sscanf(token, format, direction, entry->before, entry->after);
        printf("get_remap_table_m. n=%d, direction=%s, before=%s, after=%s\n", n, direction, entry->before, entry->after);
        entry->direction = atoi(direction);
        list_add_tail(&(entry->list), head);
    }
    free(nvram_data);
    return head;
}

void get_pattern(char *pattern)
{
    //从nvram中读取信息
    int ret = scfgmgr_getall(&nvram_data);
    if(ret < 0 || NULL == nvram_data)
    {
        printf("get nvram failed, ret=%d\n");
        return NULL;
    }
    char *regex = value_parser("regex");
    if(NULL == regex)
    {
        strcpy(pattern, "");
        free(nvram_data);
        return;
    }
    char *p = strstr(regex, "1,");
    if(p)
    {
        char *p_start = p + 2;
        char *p_end = strchr(p_start, ',');
        if(p_end)
            strncpy(pattern, p_start, p_end - p_start);
        else
            strcpy(pattern, "");
    }
    else
        strcpy(pattern, "");
    free(nvram_data);
    return;
}

*/
//一般不会使用此函数来释放。remap_table就是要驻留在内存中用来读取
void free_remap_table(struct list_head **head)
{
    struct list_head *pos = (*head)->next;
    struct list_head *tmp = NULL;
    while(pos != *head)
    {
        tmp = pos->next;
        remap_entry_t *entry = list_entry(pos, remap_entry_t, list);
        SAFE_FREE(entry);
        pos = tmp;
    }
    SAFE_FREE(*head);
}

