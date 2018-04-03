/*
 * =====================================================================================
 *
 *       Filename:  sslist.h
 *
 *    Description:  
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

typedef struct _node {
    data_t data;
    struct _node *next;
}node_t;

/*　头结点数据设置为空
 *  kongjiedian
 */




/* 获取指定节点
 *　获取的是节点的指针
 *  可以获取头指针　pos = 0
 */
node_t *sslist_get_elem(node_t *head, int pos)
{
    if(0 == pos) {
        return head;
    }
    int cnt = 1;
    sslist_t *t = NULL;
    for(t = head->next; t; t = t->next) {
        if(pos == cnt) {
            return t;
        }
        cnt++;
    }
    return NULL;
}

/* 在pos处插入节点 */
int sslist_insert(node_t *head, int pos, data_t data)
{
    node_t *pnode = sslist_get_elem(head, pos-1);
    node_t *node  = (node_t *)calloc(1, sizeof(node_t));
    if(NULL == node) {
        perror("cannot allocate memory calloc");
        return -1;
    }
    memcpy(&(node->data), &data, sizeof(data_t));
    node->next = pnode->next;
    pnode->next = node;
}

int sslist_delete(node_t *head , int pos)
{
    node_t *prenode = sslist_get_elem(head, pos-1);
    node_t *pnode   = prenode->next;
    prenode->next   = pnode->next; 
    free(pnode);
}




#endif

