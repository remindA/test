#ifndef _LINK_LIST_NYB_
#define _LINK_LIST_NYB_
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define LINE_LEN 128
typedef struct
{
    char buf[LINE_LEN];
}s_element;

typedef struct log_node
{
    s_element element;
    struct log_node *next;
}LOG_LIST;

typedef LOG_LIST  s_list;



int insert_first_list_element(s_list **list_head, s_element *element);
int insert_to_list_head(s_list **list_head, s_element *element);
int insert_to_list_tail(s_list **list_head, s_element *element);
int print_list_count(s_list **list_head);
int free_list_count(s_list **list_head);


#endif
