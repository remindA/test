#include "str_replace.h"

pcre2_code *get_compile_code(PCRE2_SPTR pattern, uint32_t compile_options)
{ 
    if(NULL == pattern || strlen((char *)pattern) == 0)   //strlen(NULL) will cause segment fault.but it would never happen in this code.
    {
#ifdef STRDEBUG
        printf("get_compile_code: pattern is NULL or ""\n");
#endif
        return NULL;
    }
    pcre2_code  *re;
    PCRE2_SIZE  len_pat = strlen((char *)pattern);
    PCRE2_SIZE  erroroffset;
    int         errornumber;
    re = pcre2_compile(
            pattern,        /* the pattern */
            len_pat,        /* indicates pattern is zero-terminated */
            compile_options, /* compile options */
            &errornumber,   /* for error number */
            &erroroffset,   /* for error offset */
            NULL);          /* use default compile context */

    if (re == NULL)
    {
        PCRE2_UCHAR buffer[256];
        pcre2_get_error_message(errornumber, buffer, sizeof(buffer));
        #ifdef STRDEBUG
        printf("PCRE2 compilation failed at offset %d: %s\n", (int)erroroffset, buffer);
        #endif
    }
    return re;
}


struct list_head *get_list_substring_pattern(PCRE2_SPTR subject, PCRE2_SPTR pattern, uint32_t compile_options)
{
    pcre2_code *re = get_compile_code(pattern, compile_options);
    if(NULL == re)
        return NULL;
    struct list_head *head = get_list_substring_compiled_code(subject, re);
    pcre2_code_free(re);
    return head;
}
struct list_head *get_list_substring_compiled_code(PCRE2_SPTR subject, pcre2_code *re)
{
    if(!(NULL != subject && NULL != re))
    {
        printf("get_list_sunstring_compile_code: subject==NULL or re==NULL\n");
        return NULL;
    }
    int         rc;
    PCRE2_SIZE  subject_length = strlen((char *)subject);
    PCRE2_SIZE  start_offset   = 0;
    uint32_t    op_match       = 0;
    pcre2_match_data    *match_data    = pcre2_match_data_create_from_pattern(re, NULL);
    pcre2_match_context *mcontext      = NULL;

    size_t match_cnt = 0;
    rc = pcre2_match(re, subject, subject_length,  start_offset, op_match, match_data, mcontext);
    if (rc < 0)
    {
#ifdef STRDEBUG
        switch(rc)
        {
            case PCRE2_ERROR_NOMATCH:
                printf("No match\n");
                break;
            default: 
                printf("Matching error %d\n", rc); 
                break;
        }
#endif
        pcre2_match_data_free(match_data);   /* Release memory used for the match */
        return NULL;
    }

    if (rc == 0)
    {
#ifdef STRDEBUG
        printf("ovector was not big enough for all the captured substrings\n");
#endif
    }
    /*  3. substring group */
    PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);
#ifdef STRDEBUG
    printf("rc = %d, Match succeeded at offset %d\n", rc, (int)ovector[0]);
#endif

    match_cnt++;
    struct list_head *head = (struct list_head *)malloc(sizeof(struct list_head));
#ifdef STRDEBUG
    printf("head=%p\n", head);
#endif
    if(NULL == head)
    {
        perror("malloc head");
        return NULL;
    }
    init_list_head(head);
    int length = ovector[1] - ovector[0];
    node_substr_t *node_sub = (node_substr_t *)malloc(sizeof(node_substr_t) + length + 1);
    if(NULL == node_sub)
    {
        free_list_substring(&head);  //only node head
#ifdef STRDEBUG
        printf("SAFE_FREE head = %p\n", head);
#endif
        return NULL;
    }
    memset(node_sub, 0, sizeof(node_substr_t) + length + 1);
    init_list_head(&(node_sub->list));
    node_sub->index = match_cnt;
    node_sub->startoffset = ovector[0];
    node_sub->rplstr = NULL;
    node_sub->len_substr  = length;
    strncpy(node_sub->substr, (char *)(subject + ovector[0]), node_sub->len_substr);
    list_add_tail(&(node_sub->list), head);
    int i = 0;
#ifdef STRDEBUG
    for (i = 0; i < rc; i++)
    {
        PCRE2_SPTR substring_start = subject + ovector[2*i];
        size_t substring_length = ovector[2*i+1] - ovector[2*i];
        printf("%2d: %.*s\n", i, (int)substring_length, (char *)substring_start);
    }
#endif
#ifdef NAMED_GROUP
    /*  4. looks like group引用分组和命名引用分组*/
    PCRE2_SPTR name_table;
    uint32_t   namecount;
    uint32_t   name_entry_size;

    (void)pcre2_pattern_info(re, PCRE2_INFO_NAMECOUNT, &namecount);

    if (namecount == 0) 
        printf("No named substrings\n"); 
    else
    {
        PCRE2_SPTR tabptr;
        printf("Named substrings total %d named group\n", namecount);
        (void)pcre2_pattern_info(re, PCRE2_INFO_NAMETABLE,     &name_table);
        (void)pcre2_pattern_info(re, PCRE2_INFO_NAMEENTRYSIZE, &name_entry_size);
        tabptr = name_table;
        for (i = 0; i < namecount; i++)
        {
            int n = (tabptr[0] << 8) | tabptr[1];
            printf("(%d) %*s: %.*s\n", n, name_entry_size - 3, (tabptr + 2), (int)(ovector[2*n+1] - ovector[2*n]), subject + ovector[2*n]);
            tabptr += name_entry_size;
        }
    }
#endif
    /*  5. utf8 */
    uint32_t option_bits;
    int      utf8;
    (void)pcre2_pattern_info(re, PCRE2_INFO_ALLOPTIONS, &option_bits);
    utf8 = (option_bits & PCRE2_UTF) != 0;

    /*  6. what CRLF stands for */
    uint32_t newline;
    int      crlf_is_newline;
    (void)pcre2_pattern_info(re, PCRE2_INFO_NEWLINE,    &newline);
    crlf_is_newline = (newline == PCRE2_NEWLINE_ANY) || (newline == PCRE2_NEWLINE_CRLF) || (newline == PCRE2_NEWLINE_ANYCRLF);

    for (;;)
    {
        uint32_t op_match_new = 0;                   /* Normally no options*/
        PCRE2_SIZE new_start_offset = ovector[1];   /* Start at end of previous match */
        if (ovector[0] == ovector[1])
        {
            op_match_new = PCRE2_NOTEMPTY_ATSTART | PCRE2_ANCHORED;
            if (ovector[0] == subject_length)
                break;
        }

        rc = pcre2_match(re, subject, subject_length,new_start_offset, op_match_new, match_data, NULL);
        if (rc == PCRE2_ERROR_NOMATCH)
        {
            if (op_match_new == 0) 
                break;                                          /* All matches found */
            ovector[1] = new_start_offset + 1;                  /* Advance one code unit */

            if (crlf_is_newline &&                              /* If CRLF is a newline & */
                    new_start_offset < subject_length - 1 &&    /* we are at CRLF, */
                    subject[new_start_offset] == '\r' &&
                    subject[new_start_offset + 1] == '\n')
                ovector[1] += 1;                                /* Advance by one more. */
            else if (utf8)                                  /* Otherwise, ensure we */
            {                                               /* advance a whole UTF-8 */
                while (ovector[1] < subject_length)         /* character. */
                {
                    if ((subject[ovector[1]] & 0xc0) != 0x80)
                        break;
                    ovector[1] += 1;
                }
            }
            continue;    /* Go round the loop again */
        }

        if (rc < 0)
        {
#ifdef STRDEBUG
            printf("Matching error %d\n", rc);
#endif
            pcre2_match_data_free(match_data);
            return NULL;
        }

#ifdef STRDEBUG
        printf("\nMatch succeeded again at offset %d\n", (int)ovector[0]);
#endif

        if (rc == 0)
        {
#ifdef STRDEBUG
            printf("ovector was not big enough for all the captured substrings\n");
#endif
        }
        match_cnt++;
        length = ovector[1] - ovector[0];
        node_substr_t *node_sub_temp = (node_substr_t *)malloc(sizeof(node_substr_t) + length + 1);
        if(NULL == node_sub_temp)
        {
            free_list_substring(&head); //one fail all fail
            return NULL;
        }
        memset(node_sub_temp, 0, sizeof(node_substr_t) + length + 1);
        init_list_head(&(node_sub_temp->list));
        node_sub_temp->index = match_cnt;
        node_sub_temp->startoffset = ovector[0];
        node_sub_temp->rplstr = NULL;
        node_sub_temp->len_substr = length;
        strncpy(node_sub_temp->substr, (char *)(subject + ovector[0]), node_sub_temp->len_substr);
        list_add_tail(&(node_sub_temp->list), head);
#ifdef STRDEBUG
        for (i = 0; i < rc; i++)
        {
            PCRE2_SPTR substring_start = subject + ovector[2*i];
            size_t substring_length = ovector[2*i+1] - ovector[2*i];
            printf("rc=%2d  %2d: %.*s\n", rc, i, (int)substring_length, (char *)substring_start);
        }
#endif
#ifdef NAMED_GROUP
        if (namecount == 0) 
            printf("No named substrings\n");
        else
        {
            PCRE2_SPTR tabptr = name_table;
            printf("Named substrings total %d group\n", namecount);
            for (i = 0; i < namecount; i++)
            {
                int n = (tabptr[0] << 8) | tabptr[1];
                printf("(%d) %*s: %.*s\n", n, name_entry_size - 3, tabptr + 2,
                        (int)(ovector[2*n+1] - ovector[2*n]), subject + ovector[2*n]);
                tabptr += name_entry_size;
            }
        }
#endif
    }      /* End of loop to find second and subsequent matches */

    printf("\n");
    pcre2_match_data_free(match_data);

    return head;
}


void print_list_substr_node(struct list_head *pos)
{
    node_substr_t *node = list_entry(pos,node_substr_t,list);
    printf("node_%d, list=%p, list.prev=%p, list.next=%p, startoffset=%04d, rplstr=%s, len_substr=%04d, substr=%s\n", node->index, &(node->list), node->list.prev, node->list.next, node->startoffset, node->rplstr, node->len_substr, node->substr);
}

//直接free掉整个链表对应的数据结构后台表头head。
void free_list_substring(struct list_head **head)
{
    struct list_head *pos = (*head)->next;
    while(pos != *head)
    {
#ifdef STRDEBUG
        printf("pos=%p, pos->prev=%p, pos->next=%p\n", pos, pos->prev, pos->next);
#endif
        struct list_head *temp = pos->next;
        free_list_substring_node(pos);
        pos = temp;
    }
    SAFE_FREE(*head);
#ifdef STRDEBUG
    printf("SAFE_FREE *head=%p\n", *head);
#endif
}

//释放节点pos对应的内存，必须要list_del(pos)
//说明：此链表为双链表。如果不嫌从链表中删除节点pos，而是直接free掉节点pos对应的数据结构，那么节点pos->prev若果要访问node或者节点node->next要访问node都会造成非法访问，因为node所在的内存已经被释放了。
void free_list_substring_node(struct list_head *pos)
{
    node_substr_t *node = list_entry(pos,node_substr_t,list);
    list_del(pos);
#ifdef STRDEBUG
    size_t idx = node->index;
#endif
    SAFE_FREE(node->rplstr);
    SAFE_FREE(node);
#ifdef STRDEBUG
    printf("SAFE_FREE node_%02d and it's rplstr\n", idx);
#endif
}


PCRE2_SPTR _replace_all_malloc(PCRE2_SPTR subject, struct list_head *head, const char *replace_str)
{
    int cnt = 0;
    if(0 == (cnt = list_count(head)) || NULL == subject)
    {
#ifdef STRDEBUG
        printf("_replace_all_malloc: parameters is/are wrong\n");
#endif
        return NULL;
    }
    size_t size_sum_substr = 0;
    size_t len_rpl = strlen(replace_str);
    size_t size_sum_replace = cnt * len_rpl;
    struct list_head *pos = head->next;
    list_for_each(pos, head)
    {
        node_substr_t *node = list_entry(pos,node_substr_t,list);
        size_sum_substr += node->len_substr;
    }
    size_t size_new_subject = 1 + strlen((char *)subject) - size_sum_substr + size_sum_replace;  //比较吝啬
#ifdef STRDEBUG
    printf("size_new_subject = 1 + strlen((char *)subject) - size_sum_substr + size_sum_replace\n");
    printf("%d = 1 + %d - %d + %d\n", size_new_subject, strlen((char *)subject), size_sum_substr, size_sum_replace);
#endif
    PCRE2_SPTR new_subject = (PCRE2_SPTR)malloc(size_new_subject);
    if(NULL == new_subject)
    {
        perror("malloc size_new_subject");
        return NULL;
    }
    memset((void *)new_subject, 0, size_new_subject);
    strcpy((char *)new_subject, "");
    //拼接新的字符串
    pos = head->next;
    size_t offset = 0;
    list_for_each(pos,head)
    {
#ifdef STRDEBUG
        printf("offset=%d\n", offset);
#endif
        node_substr_t *node = list_entry(pos,node_substr_t,list);
        strncat((char *)new_subject, (char *)subject + offset, node->startoffset - offset);
        strcat((char *)new_subject, replace_str);
        offset = node->startoffset + node->len_substr;
    }
    strncat((char *)new_subject, (char *)subject + offset, strlen((char *)subject) - offset);
    return new_subject;
}

PCRE2_SPTR replace_all_malloc(PCRE2_SPTR subject, PCRE2_SPTR pattern, uint32_t compile_options, const char *replace_str)
{
    struct list_head *head = get_list_substring_pattern(subject, pattern, compile_options);
    PCRE2_SPTR new_subject = _replace_all_malloc(subject, head, replace_str);
    list_print(head, print_list_substr_node);
    free_list_substring(&head);
    return new_subject;
}


PCRE2_SPTR replace_all_default_malloc(PCRE2_SPTR subject, struct list_head *head)
{
    int cnt = 0;
    if(0 == (cnt = list_count(head)) || NULL == subject)
    {
#ifdef STRDEBUG
        printf("replace_all_default_malloc: parameters is/are wrong.\n");
#endif
        return NULL;
    }
    size_t size_sum_substr = 0;
    size_t size_sum_rplstr = 0;
    struct list_head *pos = head->next;
    list_for_each(pos, head)
    {
        node_substr_t *node = list_entry(pos,node_substr_t,list);
        size_sum_substr += node->len_substr;
        if(NULL != node->rplstr)
            size_sum_rplstr += strlen(node->rplstr);
        else
            size_sum_rplstr += node->len_substr;        //为NULL则不替换(替换为本身)
    }
    if(size_sum_substr == size_sum_rplstr)              //所有节点的rplstr都为NULL,那就不替换了。
    {
#ifdef STRDEBUG
        printf("replace_all_default_malloc: all list node's rplstr is NULL\n");
#endif
        return NULL;
    }
    size_t size_new_subject = 1 + strlen((char *)subject) - size_sum_substr + size_sum_rplstr;  //比较吝啬
#ifdef STRDEBUG
    printf("size_new_subject = 1 + strlen((char *)subject) - size_sum_substr + size_sum_replace\n");
    printf("%d = 1 + %d - %d + %d\n", size_new_subject, strlen((char *)subject), size_sum_substr, size_sum_rplstr);
#endif
    PCRE2_SPTR new_subject = (PCRE2_SPTR)malloc(size_new_subject);
    if(NULL == new_subject)
    {
        perror("malloc size_new_subject");
        return NULL;
    }
    memset((void *)new_subject, 0, size_new_subject);
    strcpy((char *)new_subject, "");
    //拼接新的字符串
    pos = head->next;
    size_t offset = 0;
    list_for_each(pos,head)
    {
#ifdef STRDEBUG
        printf("offset=%d\n", offset);
#endif
        node_substr_t *node = list_entry(pos,node_substr_t,list);
        if(NULL != node->rplstr)
        {
            strncat((char *)new_subject, (char *)subject + offset, node->startoffset - offset);     //不变的+
            strcat((char *)new_subject, node->rplstr);                                              //替换串
        }
        else
            strncat((char *)new_subject, (char *)subject + offset, node->startoffset + node->len_substr - offset);  //不变的+子串(不替换)
        offset = node->startoffset + node->len_substr;
    }
    strncat((char *)new_subject, (char *)subject + offset, strlen((char *)subject) - offset);
    return new_subject;
}

/*
PCRE2_SPTR replace_all_default_malloc(PCRE2_SPTR subject, PCRE2_SPTR pattern)
{
    struct list_head *head = get_list_substring_pattern(subject, pattern);
    PCRE2_SPTR new_subject = _replace_all_default_malloc(subject, head, replace_str);
    list_print(head, print_list_substr_node);
    free_list_substring(&head);
    return new_subject;
}
*/

PCRE2_SPTR _replace_index_malloc(PCRE2_SPTR subject, struct list_head *head, size_t index, const char *replace_str)
{
    int cnt = 0;
    if(0 == (cnt = list_count(head)) || NULL == subject)
    {
#ifdef STRDEBUG
        printf("_replace_index_malloc: parameters is/are wrong.\n");
#endif
        return NULL;
    }

    if(index < 0 || index > cnt)
    {
#ifdef STRDEBUG
        printf("_replace_index_malloc: index=%d out of range cnt=%d\n", index, cnt);
        return NULL;
#endif
    }
    size_t size_sum_substr = 0;
    size_t len_rpl = strlen(replace_str);
    size_t size_sum_replace = 1 * len_rpl;
    struct list_head *pos = head->next;
    node_substr_t *node = NULL;
    list_for_each(pos, head)
    {
        node = list_entry(pos,node_substr_t,list);
        if(node->index == index)
        {
            size_sum_substr += node->len_substr;
            break;
        }
    }
    size_t size_new_subject = 1 + strlen((char *)subject) - size_sum_substr + size_sum_replace;  //比较吝啬
    PCRE2_SPTR new_subject = (PCRE2_SPTR)malloc(size_new_subject);
    if(NULL == new_subject)
    {
        perror("malloc size_new_subject");
        return NULL;
    }
    memset((void *)new_subject, 0, size_new_subject);
    strcpy((char *)new_subject, "");
    //拼接新的字符串
    size_t offset = 0;
    strncat((char *)new_subject, (char *)subject + offset, node->startoffset - offset);
    strcat((char *)new_subject, replace_str);
    offset = node->startoffset + node->len_substr;
    strncat((char *)new_subject, (char *)subject + offset, strlen((char *)subject) - offset);
    return new_subject;
}

PCRE2_SPTR replace_index_malloc(PCRE2_SPTR subject, PCRE2_SPTR pattern, uint32_t compile_options, size_t index, const char *replace_str)
{
    struct list_head *head = get_list_substring_pattern(subject, pattern, compile_options);
    if(head == NULL)
        return NULL;
    PCRE2_SPTR new_subject = _replace_index_malloc(subject, head, index, replace_str);
    free_list_substring(&head);
    return new_subject;
}

void pad_list_rplstr_malloc(struct list_head *head, pad_rplstr_t pad, struct list_head *table_head)
{
    if(NULL == head || NULL == pad || (table_head->next == table_head) || (table_head->prev == table_head))
    {
        printf("pad_list_rplstr_malloc argv wrong\n");
#ifdef STRDEBUG
        printf("head=%p, pad=%p, table_head->next=%p, table_head->prev=%p\n", head, pad, table_head->next, table_head->prev);
#endif
        return;
    }
    struct list_head *pos;
    list_for_each(pos,head)
    {
        node_substr_t *node = list_entry(pos,node_substr_t,list);
        pad(node, table_head);
    }
}


