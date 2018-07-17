#define PCRE2_CODE_UNIT_WIDTH 8
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <pcre2.h>
#include "list.h"
#include "safe_free.h"

typedef struct node_substr{
    struct list_head list;
    char group[16];
    size_t index;
    //size_t line_index;
    size_t startoffset;
    size_t len_substr;
    char   substr[0];
}node_substr_t;


void usage(const char *process);
void err_quit(const char *api);
int main(int argc, char **argv)
{
    //获取pattern和subject字符串
    if(argc != 3)
        usage(argv[0]);
    int fd_pattern = open(argv[1], O_RDONLY);
    int fd_subject = open(argv[2], O_RDONLY);
    if(fd_pattern < 0)
        err_quit("open pattern");
    if(fd_subject < 0)
        err_quit("open subject");

    struct stat stat_pattern;
    struct stat stat_subject;
    stat(argv[1], &stat_pattern);
    stat(argv[2], &stat_subject);

    char *pat = (char *)malloc(stat_pattern.st_size);
    char *sub = (char *)malloc(stat_subject.st_size + 1);
    if(NULL == pat)
        err_quit("malloc pattern");
    if(NULL == sub)
        err_quit("malloc subject");
    memset(pat, 0, stat_pattern.st_size);
    memset(sub, 0, stat_subject.st_size + 1);
    printf("pat =%p\n", pat);
    printf("sub =%p\n", sub);
    if(read(fd_pattern, pat, stat_pattern.st_size - 1) < 0)     //读pattern时不需要把换行符读取进来
        err_quit("read pattern");
    if(read(fd_subject, sub, stat_subject.st_size) <0)
        err_quit("read subject");
    close(fd_pattern);
    close(fd_subject);
    printf("pattern: %s, strlen()=%d\n", pat, strlen(pat));


    int i;


    /*  1. compile */
    pcre2_code  *re;
    PCRE2_SPTR  pattern = (PCRE2_SPTR)pat;
    PCRE2_SIZE  len_pat = strlen((char *)pattern);
    uint32_t    op_comp = 0;
    PCRE2_SIZE  erroroffset;
    int         errornumber;
    //op_comp |= PCRE2_MULTILINE | PCRE2_FIRSTLINE;

    re = pcre2_compile(
            pattern,        /* the pattern */
            len_pat,        /* indicates pattern is zero-terminated */
            op_comp,        /* default options */
            &errornumber,   /* for error number */
            &erroroffset,   /* for error offset */
            NULL);          /* use default compile context */

    if (re == NULL)
    {
        PCRE2_UCHAR buffer[256];
        pcre2_get_error_message(errornumber, buffer, sizeof(buffer));
        printf("PCRE2 compilation failed at offset %d: %s\n", (int)erroroffset, buffer);
        return 1;
    }

    /*  2. match */
    int         rc;
    PCRE2_SPTR  subject        = (PCRE2_SPTR)sub;
    PCRE2_SIZE  subject_length = strlen((char *)subject);
    PCRE2_SIZE  start_offset   = 0;
    uint32_t    op_match       = 0;
    pcre2_match_data    *match_data    = pcre2_match_data_create_from_pattern(re, NULL);
    pcre2_match_context *mcontext      = NULL;

    size_t match_cnt = 0;
    rc = pcre2_match(re, subject, subject_length,  start_offset, op_match, match_data, mcontext);
    if (rc < 0)
    {
        switch(rc)
        {
            case PCRE2_ERROR_NOMATCH: 
                printf("No match\n"); 
                break;
            default: 
                printf("Matching error %d\n", rc); 
                break;
        }
        pcre2_match_data_free(match_data);   /* Release memory used for the match */
        pcre2_code_free(re);                 /* data and the compiled pattern. */
        return 1;
    }


    if (rc == 0)
        printf("ovector was not big enough for all the captured substrings\n");

    /*  3. substring group */
    PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);
    printf("rc = %d, Match succeeded at offset %d\n", rc, (int)ovector[0]);

    match_cnt++;
    struct list_head *head = (struct list_head *)malloc(sizeof(struct list_head));
    printf("head=%p\n", head);
    if(NULL == head)
        err_quit("malloc head");
    init_list_head(head);
    int length = ovector[1] - ovector[0];
    node_substr_t *node_sub = (node_substr_t *)malloc(sizeof(node_substr_t) + length + 1);
    if(NULL == node_sub)
        err_quit("malloc node_sub");
    node_sub->index = match_cnt;
    node_sub->startoffset = ovector[0];
    node_sub->len_substr  = length;
    strncpy(node_sub->substr, (char *)(subject + ovector[0]), node_sub->len_substr);
    list_add_tail(&(node_sub->list), head);
    /*
    for (i = 0; i < rc; i++)
    {
        PCRE2_SPTR substring_start = subject + ovector[2*i];
        size_t substring_length = ovector[2*i+1] - ovector[2*i];
        printf("%2d: %.*s\n", i, (int)substring_length, (char *)substring_start);
    }
    */

    /*  4. looks like group引用分组和命名引用分组*/
    PCRE2_SPTR name_table;
    uint32_t   namecount;
    uint32_t   name_entry_size;

    (void)pcre2_pattern_info(re, PCRE2_INFO_NAMECOUNT, &namecount);

    if (namecount == 0) { 
        printf("No named substrings\n"); 
    }
    else
    {
        PCRE2_SPTR tabptr;
        (void)pcre2_pattern_info(re, PCRE2_INFO_NAMETABLE,     &name_table);
        (void)pcre2_pattern_info(re, PCRE2_INFO_NAMEENTRYSIZE, &name_entry_size);
        tabptr = name_table;
        for (i = 0; i < namecount; i++) {
            int n = (tabptr[0] << 8) | tabptr[1];
            int ll = (int)(ovector[2*n+1] - ovector[2*n]); 
            printf("%s: %.*s\n", 
                    (tabptr + 2), 
                    ll,
                    subject + ovector[2*n]);
            if(ll > 0) {
                strcpy(node_sub->group, tabptr+2);
            }
            tabptr += name_entry_size;
        }
    }

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

        //若上次匹配的是空字符串""(ovector[0]==ovector[1]),下次不要匹配空串
        if (ovector[0] == ovector[1])
        {
            op_match_new = PCRE2_NOTEMPTY_ATSTART | PCRE2_ANCHORED;
            //空串且到达尾部，结束。
            if (ovector[0] == subject_length)
                break;
        }

        rc = pcre2_match(re, subject, subject_length,new_start_offset, op_match_new, match_data, NULL);
        if (rc == PCRE2_ERROR_NOMATCH)
        {
            if (op_match_new == 0) 
                break;                                          /* All matches found */
            //ovector[1]第一次advance一次
            ovector[1] = new_start_offset + 1;                  /* Advance one code unit */

            //如果处于换行\r\n位置,那么再advance一次，到达新行
            if (crlf_is_newline &&                              /* If CRLF is a newline & */
                    new_start_offset < subject_length - 1 &&    /* we are at CRLF, */
                    subject[new_start_offset] == '\r' &&
                    subject[new_start_offset + 1] == '\n')
                ovector[1] += 1;                                /* Advance by one more. */
            /****************************************************************************
              Unicode符号范围 | UTF-8编码方式
              (十六进制) | （二进制)
              0000 0000-0000 007F:0xxxxxxx												    //while()执行1次,直接break;   vector[1] 共advance 1 字节 　(此utf-8字符长度1字节)
              0000 0080-0000 07FF:110xxxxx 10xxxxxx                                         //while()执行2次,第2次break;　vector[1] 共advance 2 字节   (此utf-8字符长度2字节)　
              0000 0800-0000 FFFF:1110xxxx 10xxxxxx 10xxxxxx                                //while()执行3次,第3次break;  vector[1] 共advance 3 字节 　(此utf-8字符长度3字节)
              0001 0000-001F FFFF:11110xxx 10xxxxxx 10xxxxxx 10xxxxxx                       //while()执行4次,第4次break;  vector[1] 共advance 4 字节 　(此utf-8字符长度4字节)
              0020 0000-03FF FFFF:111110xx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx              //while()执行5次.第5次break;  vector[1] 共advance 5 字节 　(此utf-8字符长度5字节)
              0400 0000-7FFF FFFF:1111110x 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx     //while()执行6次,第6次break;  vector[1] 共advance 6 字节 　(此utf-8字符长度6字节)
             **************************************************************************/
            //或者是utf-8编码的字符串，可能需要advance多次
            else if (utf8)                                  /* Otherwise, ensure we */
            {                                               /* advance a whole UTF-8 */
                while (ovector[1] < subject_length)         /* character. */
                {
                    //aaa:如果是utf-8编码
                    if ((subject[ovector[1]] & 0xc0) != 0x80)
                        break;
                    ovector[1] += 1;
                }
            }
            continue;    /* Go round the loop again */
        }

        if (rc < 0)
        {
            printf("Matching error %d\n", rc);
            pcre2_match_data_free(match_data);
            pcre2_code_free(re);
            return 1;
        }

        printf("\nMatch succeeded again at offset %d\n", (int)ovector[0]);

        if (rc == 0)
            printf("ovector was not big enough for all the captured substrings\n");

        match_cnt++;
        length = ovector[1] - ovector[0];
        node_substr_t *node_sub_temp = (node_substr_t *)malloc(sizeof(node_substr_t) + length + 1);
        if(NULL == node_sub_temp)
            err_quit("malloc node_sub_temp");
        node_sub_temp->startoffset = ovector[0];
        node_sub_temp->index = match_cnt;
        node_sub_temp->len_substr = length;
        strncpy(node_sub_temp->substr, (char *)(subject + ovector[0]), node_sub_temp->len_substr);
        list_add(&(node_sub_temp->list), head);
        /*
        for (i = 0; i < rc; i++)
        {
            PCRE2_SPTR substring_start = subject + ovector[2*i];
            size_t substring_length = ovector[2*i+1] - ovector[2*i];
            printf("rc=%2d  %2d: %.*s\n", rc, i, (int)substring_length, (char *)substring_start);
        }
        */

        if (namecount == 0) { 
            printf("No named substrings\n");
        }
        else {
            PCRE2_SPTR tabptr = name_table;
            //printf("Named substrings total %d group\n", namecount);
            for (i = 0; i < namecount; i++) {
                int n = (tabptr[0] << 8) | tabptr[1];
                int ll = (int)(ovector[2*n+1] - ovector[2*n]); 
                printf("%s: %.*s\n", 
                        /*name_entry_size - 3, */
                        tabptr + 2,
                        ll,
                        subject + ovector[2*n]);
                if(ll > 0) {
                    strcpy(node_sub_temp->group, tabptr+2);
                }
                tabptr += name_entry_size;
            }
        }
    }      /* End of loop to find second and subsequent matches */

    printf("\n");
    struct list_head *pos;
    printf("head->prev=%p\nhead->next=%p\n", head->prev, head->next);
    list_for_each(pos, head)
    {
        //printf("node\n");
        node_substr_t *temp = list_entry(pos,node_substr_t,list);
        //printf("%p %p", temp, pos);
        printf("index=%d,\tstartoffset=%d,\tlen_substr=%d,\tgroup=%s,\tsubstr=%s\n", 
                temp->index, temp->startoffset, temp->len_substr, temp->group, temp->substr);
    }
    pos = head->next;
    while(pos != head)
    {
        struct list_head *temp = NULL;
        node_substr_t *node = list_entry(pos, node_substr_t, list);
        temp = pos->next;
        size_t idx = node->index;
        SAFE_FREE(node);
        pos = temp;

    }
    SAFE_FREE(head);
    SAFE_FREE(pat);
    SAFE_FREE(sub);
    pcre2_match_data_free(match_data);
    pcre2_code_free(re);
    return 0;
}


void err_quit(const char *api)
{
    perror(api);
    exit(1);
}

void usage(const char *process)
{
    printf("Usage: %s pattern_file subject_file\n", process);
    exit(1);
}
