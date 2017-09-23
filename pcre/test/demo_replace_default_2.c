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
#include "str_replace.h"
#include "err_quit.h"
#include "pad_rplstr.h"

void usage(const char *process)
{
    printf("Usage: %s pattern_file subject_file replace_file\n", process);
    exit(1);
}

remap_t remap_table[] = {
    {"niuyaben", "牛亚犇"},
    {"richard", "*RICHARD*"},
    {"牛亚犇", "刘呀奔"}
};
int main(int argc, char **argv)
{
    //获取pattern和subject字符串
    if(argc != 4)
        usage(argv[0]);
    int fd_pattern = open(argv[1], O_RDONLY);
    int fd_subject = open(argv[2], O_RDONLY);
    int fd_replace = open(argv[3], O_RDONLY);
    if(fd_pattern < 0)
        err_quit("open pattern");
    if(fd_subject < 0)
        err_quit("open subject");
    if(fd_replace < 0)
        err_quit("open replace");

    struct stat stat_pattern;
    struct stat stat_subject;
    struct stat stat_replace;
    stat(argv[1], &stat_pattern);
    stat(argv[2], &stat_subject);
    stat(argv[3], &stat_replace);

    char *pat = (char *)malloc(stat_pattern.st_size);
    char *sub = (char *)malloc(stat_subject.st_size + 1);
    char *rpl = (char *)malloc(stat_replace.st_size + 1);
    if(NULL == pat)
        err_quit("malloc pattern");
    if(NULL == sub)
        err_quit("malloc subject");
    if(NULL == rpl)
        err_quit("malloc replace");
    memset(pat, 0, stat_pattern.st_size);
    memset(rpl, 0, stat_replace.st_size);
    memset(sub, 0, stat_subject.st_size + 1);
    printf("pat =%p\n", pat);
    printf("rpl =%p\n", rpl);
    printf("sub =%p\n", sub);
    if(read(fd_pattern, pat, stat_pattern.st_size - 1) < 0)     //读pattern时不需要把换行符读取进来
        err_quit("read pattern");
    if(read(fd_replace, rpl, stat_replace.st_size - 1) < 0)     //读pattern时不需要把换行符读取进来
        err_quit("read replace");
    if(read(fd_subject, sub, stat_subject.st_size) <0)
        err_quit("read subject");
    close(fd_pattern);
    close(fd_subject);
    close(fd_replace);
    printf("pattern: %s, strlen()=%d\n", pat, strlen(pat));
    printf("replace: %s, strlen()=%d\n", rpl, strlen(rpl));

    PCRE2_SPTR subject = (PCRE2_SPTR)sub;
    PCRE2_SPTR pattern = (PCRE2_SPTR)pat;
    struct list_head *head = get_list_substring_pattern(subject, pattern, PCRE2_UTF);
    //匹配失败或者只有头结点，就不用做替换
    if(head != NULL || head->next != head->next)
    {
        pad_list_rplstr_malloc(head, pad_remap_rplstr_malloc, remap_table, 3);
        list_print(head, print_list_substr_node);
        PCRE2_SPTR new_subject = replace_all_default_malloc(subject, head);
        if(NULL != new_subject)
        {
            //using new_subject
            FILE *fp = fopen("replace_file", "w+");
            if(NULL == fp)
                perror("fopen replace_file");
            else
            {
                fprintf(fp, "%s", (char *)new_subject);
                fclose(fp);
            }
            SAFE_FREE(new_subject);
        }
        else
        {
            //using subject
        }
    }
    else
    {
        //using subject;
    }
    pattern =   NULL;
    pcre2_code *re = get_compile_code(pattern, 0);
    SAFE_FREE(pat);
    SAFE_FREE(sub);
    SAFE_FREE(rpl);
    SAFE_FREE(head);
    return 0;

}


