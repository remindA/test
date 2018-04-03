/*
 * =====================================================================================
 *
 *       Filename:  sqlist.c
 *
 *    Description:  线性表顺序存储结构
 *
 *        Version:  1.0
 *        Created:  2018年03月31日 20时09分38秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */


sqlist_t *sqlist_create_init(void)
{
    sqlist_t *list = (sqlist_t *)calloc(1, sizeof(sqlist_t));
    if(NULL == list) {
        printf("cannot allcate memory\n");
        return NULL;
    }
    return list;
}


/* 获取第pos个位置的元素, pos=1,2,3... */
int sqlist_get_elem(const sqlist_t *list, int pos, elem_t *e)
{
    if(pos < 1 || pos > list->len) {
        return -1;
    }
    *e = list->elem[pos - 1];
    return 0;
}


/* 向第pos个位置插入新元素, pos=1,2,3... */
int sqlist_insert(const sqlist_t *list, int pos, elem_t e)
{
    if(list->len >= SQLIST_MAX_SIZE){
        printf("sqlist is full\n");
        return -1;
    }
    /* 超范围 */
    if(pos < 1 || pos > list->len + 1) {
        printf("insert postion not in range\n");
        return -1;
    }
    int i;
    for(i = list->len-1; i > pos-1; i--) {
        memcpy(&(list->elem[i + 1]), &(list->elem[i]), sizeof(elem_t));
    }
    memcpy(&(list->elem[pos-1]), &e, sizeof(elem_t));
    list->len += 1;
    return 0;
}

inline int sqlist_push(const sqlist_t *list, elem_t e)
{
    return sqlist_insert(list, list->len, e);
}


int sqlist_delete(const sqlist_t *list, int pos)
{
    /* 检查 */
    if(0 == list->len) {
        printf("list is alrerady empty\n");
        return -1;
    }
    if(pos < 1 || pos > list->len + 1) {
        printf("delete position is not in range\n");
        return -1;
    }
    int i;
    for(i = pos-1; i < list->len-1; i++) {
        memcpy(&(list->elem_t[i]), &(list->elem[i+1]), sizeof(elem_t));
    }
    memset(&(list->elem[list->len-1]), 0, sizeof(elem_t));
    list->len -= 1;
}

inline int sqlist_pop(const sqlist_t *list, elem_t *e)
{
}
