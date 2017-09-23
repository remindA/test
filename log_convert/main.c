#include "link_list.h"






int main(int argc , char **argv)
{
    if(argc < 2)
    {
        printf("need a file\n");
        exit(EXIT_FAILURE);
    }
    /* 1.fopen */
    FILE *fp = fopen(argv[argc - 1], "r");
    if(fp == NULL)
    {
        perror("fopen");
        exit(EXIT_FAILURE);
    }
    /* 2.create and initialize list */
     char line[LINE_LEN] = {0};
    s_list *list_head = NULL;     //create a list and initialize to be a empty list.
    s_element ele;
    memset(&ele, 0, sizeof(s_element));
    int order = 1;
    while(fgets(line, LINE_LEN, fp) != NULL)
    {
        strncpy(ele.buf, line, strlen(line) + 1);
        //printf("%s", line);
        if(order)
            insert_to_list_tail(&list_head, &ele);
        else
            insert_to_list_head(&list_head, &ele);
        memset(line, 0, sizeof(line));
        memset(&ele, 0, sizeof(ele));
    }
    fclose(fp);


    s_list *tmp = list_head;
    while(tmp != NULL)
    {
        printf("%s", tmp->element.buf);
        tmp = tmp->next;
    }

    print_list_count(&list_head);
    free_list_count(&list_head);

    return 0;
}

