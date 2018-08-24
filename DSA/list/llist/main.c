/*
 * =====================================================================================
 *
 *       Filename:  main.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年08月23日 16时59分48秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  NYB (), niuyabeng@126.com
 *   Organization:  
 *
 * =====================================================================================
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

struct linkedlist {
    int val;
    struct linkedlist *next;
};

typedef struct linkedlist MyLinkedList;

/* 头结点不存放数据 */

/** Initialize your data structure here. */
MyLinkedList* myLinkedListCreate() {
    MyLinkedList *head = (MyLinkedList *)calloc(1, sizeof(MyLinkedList));
    if(NULL == head){
        perror("calloc()");
        return NULL;
    }
    head->next = NULL;
    return head;
}

/** Get the value of the index-th node in the linked list. If the index is invalid, return -1. */
int myLinkedListGet(MyLinkedList* obj, int index) {
    if(index < 0 || obj == NULL || obj->next == NULL) {
        return -1;
    }
    int idx = -1;
    MyLinkedList *node;
    for(node = obj->next; node != NULL; node = node->next) {
        idx++;
        if(idx == index) {
            return node->val;
        }
    }
    return -1;
}

/** Add a node of value val before the first element of the linked list. After the insertion, the new node will be the first node of the linked list. */
void myLinkedListAddAtHead(MyLinkedList* obj, int val) {
    MyLinkedList *new = (MyLinkedList *)calloc(1, sizeof(MyLinkedList));
    if(NULL == new) {
        perror("calloc()");
        return;
    }
    new->val = val;
    new->next = NULL;
    new->next = obj->next;
    obj->next = new;
}

/** Append a node of value val to the last element of the linked list. */
void myLinkedListAddAtTail(MyLinkedList* obj, int val) {
    MyLinkedList *new = (MyLinkedList *)calloc(1, sizeof(MyLinkedList));
    if(NULL == new) {
        perror("calloc()");
        return;
    }
    new->val = val;
    new->next = NULL;
    MyLinkedList *tmp;
    for(tmp = obj; tmp->next != NULL; tmp = tmp->next) {
        ;
    }
    tmp->next = new;
}

/** Add a node of value val before the index-th node in the linked list. If index equals to the length of linked list, the node will be appended to the end of linked list. If index is greater than the length, the node will not be inserted. */
void myLinkedListAddAtIndex(MyLinkedList* obj, int index, int val) {
    /* check index */
    if(index < 0 || obj == NULL) {
        return;
    }
    int idx = -1;
    MyLinkedList *pre;
    MyLinkedList *tmp;
    for(pre = obj, tmp = pre->next; tmp != NULL; pre = pre->next, tmp = pre->next) {
        idx++;
        if(idx == index) {
            break;
        }
    }
    
    if(index == idx || index-1 == idx) {
        MyLinkedList *new = (MyLinkedList *)calloc(1, sizeof(MyLinkedList));
        if(NULL == new) {
            perror("calloc()");
            return;
        }
        new->val = val;
        new->next = NULL;
        new->next = pre->next;
        pre->next = new; 
    }
    else {
        return;
    }
    
    /* create node */
    /* insert node */
}

/** Delete the index-th node in the linked list, if the index is valid. */
void myLinkedListDeleteAtIndex(MyLinkedList* obj, int index) {
    if(index < 0 || obj == NULL || obj->next == NULL) {
        return;
    }
    int idx = -1;
    MyLinkedList *tmp;
    MyLinkedList *pre;
    for(pre = obj, tmp = obj->next; tmp != NULL; pre = pre->next, tmp = tmp->next) {
        idx++;
        if(idx == index) {
            /*  */
            break;
        }
    }
    printf("idx = %d, index = %d\n", idx, index);
    if(index != idx) {
        printf("not match\n");
        return;
    }
    printf("delete\n");
    pre->next = tmp->next;
    free(tmp);
}

void myLinkedListFree(MyLinkedList* obj) {
    MyLinkedList *tmp;
    MyLinkedList *node = obj;
    while(node->next) {
        tmp = node;
        node = node->next;
        free(tmp);
    }
    free(node);
}


void myLinkedListPrint(MyLinkedList* obj) {
    MyLinkedList *tmp;
    MyLinkedList *node = obj;
    while(node->next) {
        tmp = node;
        node = node->next;
        printf("%02d,", node->val);
    }
    printf("\n");
}

/**
 * Your MyLinkedList struct will be instantiated and called as such:
 * struct MyLinkedList* obj = myLinkedListCreate();
 * int param_1 = myLinkedListGet(obj, index);
 * myLinkedListAddAtHead(obj, val);
 * myLinkedListAddAtTail(obj, val);
 * myLinkedListAddAtIndex(obj, index, val);
 * myLinkedListDeleteAtIndex(obj, index);
 * myLinkedListFree(obj);
 */

int main(int argc, char **argv)
{
    MyLinkedList *list = myLinkedListCreate();
    myLinkedListPrint(list);
    int i;
    for(i = 0; i < 50; i++) {
        //myLinkedListAddAtIndex(list, 0, i);
        myLinkedListAddAtTail(list, i);
        myLinkedListPrint(list);
    }
    printf("\n\n");
    myLinkedListDeleteAtIndex(list, 49);
    myLinkedListPrint(list);

    return 0;
}
