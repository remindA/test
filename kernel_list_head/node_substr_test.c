#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "include.h"
#include "list.h"

void err_quit(const char *api)
{
    perror(api);
    exit(1);
}

typedef struct node_substr
{
    struct list_head list;
    size_t startoffset;
    size_t endoffset;
    char   substr[0];
}node_substr_t;

int main(int argc, char **argv)
{
    /*
    char *substr_1 = "test";
    int   len_substr_1 = strlen(substr_1);
    char *substr_2 = "TEST";
    node_substr_t *node_substr_1 = (node_substr_t *)malloc(sizeof(node_substr_t) + len_substr_1 + 1);
    if(NULL == node_substr_1)
        err_quit("malloc node_1");

    init_list_head(&(node_substr_1->list));
    node_substr_1->startoffset = 12;
    node_substr_1->endoffset = node_substr_1->startoffset + len_substr_1;
    strcpy(node_substr_1->substr, substr_1);

    printf("%slist.next  =%p\n", STR(node_substr_1->), node_substr_1->list.next);
    printf("%slist.prev  =%p\n", STR(node_substr_1->), node_substr_1->list.prev);
    printf("%sstartoffset=%d\n", STR(node_substr_1->), node_substr_1->startoffset);
    printf("%sendoffset  =%d\n", STR(node_substr_1->), node_substr_1->endoffset);
    printf("%ssubstr     =%s\n", STR(node_substr_1->), node_substr_1->substr);
    free(node_substr_1);
*/
    //链表头
    struct list_head *head = (struct list_head *)malloc(sizeof(struct list_head));
    init_list_head(head);
    int i = 0;
    for(i = 0; i < 3; i++)
    {
        char arry[123] = {0};
        sprintf(arry, "test%.*d", i + 2, i);
        printf("%s\n", arry);
        int len = strlen(arry);
        node_substr_t *node = (node_substr_t *)malloc(sizeof(node_substr_t) + len + 1);
        if(NULL == node)
            err_quit("malloc node");
        node->startoffset = 0;
        node->endoffset   = len;
        strcpy(node->substr, arry);
        list_add(&(node->list), head);
        printf("node_%d->list.prev=%p\n", i, node->list.prev);
        printf("node_%d->list.next=%p\n", i, node->list.next);
        printf("head->prev=%p\n", head->prev);
        printf("head->next=%p\n", head->next);
    }

    struct list_head *pos = NULL;
    list_for_each(pos, head)
    {
        printf("node\n");
    }

    return 0;
}
    
