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


void usage(const char *process)
{
    printf("Usage: %s pattern_file subject_file\n", process);
    exit(1);
}
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

    PCRE2_SPTR subject = (PCRE2_SPTR)sub;
    PCRE2_SPTR pattern = (PCRE2_SPTR)pat;
    PCRE2_SPTR new_subject = replace_all_malloc(subject, pattern, 0, "NIU");
    if(NULL != new_subject)
    {
        
        printf("%s\n", (char *)new_subject);
        FILE *fp = fopen("replace_file", "w+");
        if(NULL == fp)
            perror("fopen replace_file");
        else
        {
            fprintf(fp, "%s", (char *)new_subject);
            fclose(fp);
        }
    }
    SAFE_FREE(pat);
    SAFE_FREE(sub);
    SAFE_FREE(new_subject);
    return 0;

}


