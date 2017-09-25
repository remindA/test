#include "pad_rplstr.h"

//remap_t remap_tab[LEN_REMAP];         //512条记录对于nvram来说太大了。


//typedef void (*pad_rplstr_t)(node_substr_t *node, void *table, size_t len);
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


//typedef void (*pad_rplstr_t)(node_substr_t *node, struct list_head *head_table);
//这个函数将要取代上面的函数
void pad_remap_rplstr_m(node_substr_t *node, struct list_head *head_table)
{
    struct list_head *pos;
    list_for_each(pos, head_table)
    {
        remap_entry_t *entry = list_entry(pos, remap_entry_t, list);
        if(strcmp(node->substr, entry->before) == 0)
        {
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
        SAFE_FREE(head);
        return NULL;
    }
    char *remap = value_parser("ipmaps");

    //分割，取出，添加到链表remap_table
    char *str, *token;
    char *saveptr;
    int i = 0; 
    for(i = 1, str = remap; ; i++, str = NULL)
    {
        token = strtok_r(str, ";", &saveptr);
        if(NULL == token)
        {
            SAFE_FREE(head);
            return NULL;
        }
        remap_entry_t *entry = (remap_entry_t *)malloc(sizeof(remap_entry_t));
        if(NULL == entry)
        {
            perror("malloc");
            SAFE_FREE(head);
            return NULL;
        }
        char *format = "%*,%[^,],%[^,]";
        int n = sscanf(token, format, entry->before, entry->after);
        printf("n=%d, before=%s, after=%s\n", n, entry->before, entry->after);
        list_add_tail(&(entry->list), head);
    }
    free(nvram_data);
    return head;
}

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

