
typedef struct chr_t
{
    size_t index;
    size_t offset;
}chr_t;

typedef struct s_list
{
    void   *data;
    struct s_list *next;
}s_list_t;

//单链表封装
//约定头节点不存数据


//1、初始化
//此宏创建名为name的节点并初始化
#define S_LIST_HEAD_INIT(name) \ 
    struct s_list name = {NULL, NULL};

//初始化头结点
static inline void init_s_list_head(struct s_list *head)
{
    head->data = NULL;
    head->next = NULL;
}

//通用节点操作，add
static inline void __s_list_add(struct s_list *head, struct s_list *new)
{
    struct s_list *temp = head->next;
    head->next = new;
    new->next  = temp;
}

struct chr
{
    size_t index;
    size_t offset;
}chr_t;

int get_s_list_chr()
{

    char str[] = "sjcdnjcnwjwsco\ndjfbnnsk\nsjhdwj";
    int i = 0;
    int cnt = 1;
    char c = 0;
    size_t len = strlen(str);
    for(i = 0; i < len; i++)
    {
        if(stri[i] == '\n')
        {
            struct s_list *new = (struct s_list *)malloc(sizeof(struct s_list));
            struct chr *data = (struct chr *)malloc(sizeof(struct chr));
            data->index = cnt;
            data->offset = i;
            new->data = data;
            s_list_add(head_chr, new);
            s_list_add_tail(head_chr, new);
        }
    }
}

static inline void list_free(struct s_list *head)
{
    struct s_list *pos = head->next;
    while(pos != NULL)
    {
        struct s_list *temp = pos->next;
        SAFE_FREE(pos->data);
        SAFE_FREE(pos);
        pos = temp;
    }
}

typedef void (*fun_print_t)(void *data);

//对于不同的data类型的数据编写不同的fun_print即可。
void s_list_print(struct s_list *head, fun_print_t print)
{
    struct s_list *pos = head->next;
    while(pos != NULL)
    {
        print(pos->data);
        pos = pos->next;
    }
}

void print_chr_t(void *data)
{
    chr_t *dat = (chr_t *)data;
    printf("chr->index=%d, chr->offset=%d\n", dat->index, dat->offset);
}

