/*
 * =====================================================================================
 *
 *       Filename:  slist.h
 *
 *    Description:  单向循环链表 
 *
 *        Version:  1.0
 *        Created:  2018年04月01日 14时50分41秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#ifndef _SL_LIST_H_
#define _SL_LIST_H_

/*
 * 头结点不存放数据
 */
struct slist_head {
    struct slist_head *next;
};

#define offsetof(type,element) \
    ((size_t)&(((type *)0)->element))

#define container_of(ptr,type,element) ({\
    const typeof(((type *)0)->element)*__mptr = (ptr); \
    (type *)((char *)__mptr - offsetof(type,element));})

#define POISON_POINTER_DELTA 0
#define LIST_POISON1 ((void *)0x00100100 + POISON_POINTER_DELTA)
#define LIST_POISON2 ((void *)0x00200200 + POISON_POINTER_DELTA)

#define slist_entry(ptr,type,element) \
    container_of(ptr,type,element)

#define slist_for_each(pos,head) \
    for(pos = (head)->next; pos != (head); pos = pos->next)

static inline void __slist_add(struct slist_head *prev, struct slist_head *next, struct slist_head *new)
{
    prev->next = new;
    new->next = next;
}

/* 头插 */

/* 尾插 */
static inline void slist_add_append(struct slist_head *pos, struct slist_head *new)
{
    __slist_add(pos, pos->next, new); 
}

/* slist_add_first() 插入的新节点作为第一个节点 */
static inline void slist_add_first(struct slist_head *head, struct slist_head *new)
{
    __slist_add(head, head->next, new);
}

static inline void slist_add_last(struct slist_head *head, struct slist_head *new)
{
    struct slist_head *pos = head->next;
    while((pos = pos->next) != head) ;

}

static inline void __slist_del(struct slist_head *prev, struct slist_head *next) 
{
    prev->next = next;

}

static inline void slist_del_next(struct slist_head *head, struct slist_head *pos)
{
    if(head != pos->next) {
        __slist_del(pos, pos->next->next);
    }
    else {
        __slist_del(head, head->next->next);
    }
}



#endif

