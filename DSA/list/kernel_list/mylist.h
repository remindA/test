#ifndef _LIST_H_
#define _LIST_H_

/*
 * 有两个版本的函数
 *      链表的表头不存放任何数据
 *      链表头结点存放数据的函数含有"2"
 */


struct list_head
{
    struct list_head *next;
    struct list_head *prev;
};

typedef void (*list_print_t)(struct list_head *pos);

#define offsetof(type,element) \
    ((size_t)&(((type *)0)->element))

#define container_of(ptr,type,element) ({\
    const typeof(((type *)0)->element)*__mptr = (ptr); \
    (type *)((char *)__mptr - offsetof(type,element));})

#define POISON_POINTER_DELTA 0
#define LIST_POISON1 ((void *)0x00100100 + POISON_POINTER_DELTA)
#define LIST_POISON2 ((void *)0x00200200 + POISON_POINTER_DELTA)

//LIST_HEAD创建头结点，并初始化
#define LIST_HEAD_INIT(name) {&(name), &(name)}
#define LIST_HEAD(name) \
    struct list_head name = LIST_HEAD_INIT(name)
#define INIT_LIST_HEAD(head) init_list_head(head)
/*
LIST_HEAD(name)展开就是
struct list_head name = {&(name), &(name)};
*/

//1、初始化链表头结点
static inline void init_list_head(struct list_head *list)
{
    list->next = list;
    list->prev = list;
}

//2、插入节点,通用操作
static inline void __list_add(
        struct list_head *new,
        struct list_head *prev,
        struct list_head *next)
{
    prev->next = new;
    new->next  = next;
    next->prev = new;
    new->prev  = prev;
}

//往表头插入节点不是将新节点作为表头，而是将新节点插入到表头后面
static inline void list_add(struct list_head *new, struct list_head *head)
{
    __list_add(new, head, head->next);
}

//往表尾插入节点，双向循环链表，表头的前一个节点就是表的最后一个节点
static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
    __list_add(new, head->prev, head);
}

/* 在节点后附加 */
#define list_add_append(new, pos) list_add(new, pos)
/* 在节点前插入 */
#define list_add_insert(new, pos) list_add_tail(new, pos)

 
//3、通用的删除节点
static inline void __list_del(struct list_head *prev, struct list_head *next)
{
    prev->next = next;
    next->prev = prev;
}


static inline void list_del(struct list_head *entry)
{
    __list_del(entry->prev, entry->next);
    entry->next = LIST_POISON1;
    entry->prev = LIST_POISON2;
    //对LIST_POISON1和LIST_POISON2访问都将引起页故障
}


//4、节点移动

//移动至头节点后
static inline void list_move(struct list_head *list, struct list_head *head)
{
    __list_del(list->prev, list->next);
    list_add(list, head);
}

//移动作为尾节点
static inline void list_move_tail(struct list_head *list, struct list_head *head)
{
    __list_del(list->prev, list->next);
    list_add_tail(list, head);
}



/*
 * 头结点没有数据
 */
static inline int list_empty(const struct list_head *head)
{
    return (head->next == head);
}
/*
 * 头结点有数据
 */
static inline int list_empty2(const struct list_head *head)
{
    return (head == NULL);
}

//判断节点是否是尾节点
static inline int list_is_last(const struct list_head *list, const struct list_head *head)
{
    return (list->next == head);
}

//6、遍历链表

//获取链表的数据结构
#define list_entry(ptr,type,element) \
    container_of(ptr,type,element)

//获取链表的第一个节点的数据结构(此说法不严谨，只有当ptr==head时才是获取第一个节点的数据结构)
#define list_first_entry(ptr,type,member) \
    list_entry(ptr->next,type,element)

//宏定义for循环，遍历链表

//内核中链表哈希表sk_buff表的遍历已经移除了prefetch指令
#define list_for_each(pos,head) \
    for(pos = (head)->next; pos != (head); pos = pos->next)

/*
 * 获取节点数(头结点无数据-不含头结点)
 */
static inline int list_count(const struct list_head *head)
{
    int cnt = 0;
    struct list_head *list = head->next;
    while(list != head)
    {
        list = list->next;
        cnt++;
    }
    return cnt;
}

/*
 * 获取节点数(头结点有数据-含头结点)
 */
static inline int list_count2(const struct list_head *head)
{
    if(head == NULL) {
        return 0;
    }
    int cnt = 1;
    struct list_head *list = head->next;
    while(list != head)
    {
        list = list->next;
        cnt++;
    }
    return cnt;
}

static inline void list_print(struct list_head *head, list_print_t print)
{
    struct list_head *pos = head->next;
    list_for_each(pos,head)
    {
        print(pos);
    }
}

#endif

