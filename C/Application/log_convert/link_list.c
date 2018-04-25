#include "link_list.h"

int free_list_count(s_list **list_head)
{
    s_list *node = *list_head;
    int count = 0;
    while(node != NULL)
    {
        printf("free node_%d\n", ++count);
        *list_head = node->next;        //save new list_head node
        free(node);                             //free last list_head node
        node = *list_head;                  //get new list_head node

        /* wrong grammer
        free(node);
        node = node->next;  //node already freed this no member to access.
        */
    }
}

int print_list_count(s_list **list_head)
{
    s_list *temp = *list_head;
    int count = 0;
    while(temp != NULL)
    {
        printf("node_%d\n", ++count);
        temp = temp->next;
    }
    return count;
}

int insert_first_list_element(s_list **list_head, s_element *element)
{
    if(*list_head == NULL)
    {
        *list_head = (s_list *)malloc(sizeof(s_list));
        if(NULL == *list_head)
        {
            perror("malloc");
            return -1;
        }
        memset(*list_head, 0, sizeof(list_head));
        memcpy( &((*list_head)->element), element, sizeof(s_element));
        (*list_head)->next = NULL;
        printf("first node:%s\n", (*list_head)->element.buf);
        return 0;
    }
    else
        return 0;
}


int insert_to_list_head(s_list **list_head, s_element *element)
{

    if(*list_head == NULL)
        return insert_first_list_element(list_head, element);
    else
    {
        s_list *node = (s_list *)malloc(sizeof(s_list));
        if(NULL == node)
        {
            perror("malloc");
            return -1;
        }
        memset(node, 0, sizeof(s_list));
        memcpy( &(node->element), element, sizeof(s_element));
        node->next = *list_head;
        *list_head = node;
        printf("new node:%s\n", node->element.buf);
        return 0;
    }
}


int insert_to_list_tail(s_list **list_head, s_element *element)
{
    if(*list_head == NULL)
        return insert_first_list_element(list_head, element);
    else
    {
        s_list *node = (s_list *)malloc(sizeof(s_list));
        if(node == NULL)
        {
            perror("malloc");
            return -1;
        }
        //printf("tail\n");
        memset(node, 0, sizeof(s_list));
        memcpy( &(node->element), element, sizeof(s_element));
        //printf("tail\n");
        node->next = NULL;
        s_list *tmp = *list_head;
        while(tmp->next != NULL)        //watchout
            tmp = tmp->next;
        tmp->next = node;
        printf("new node:%s\n", node->element.buf);
        return 0;
    }
}

