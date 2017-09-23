#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <regex.h>

#define FILENAME "news_baidu.html"
#define REGEXFILE "regex"
#define NMATCH  5
void err_quit(const char *api)
{
    perror(api);
    exit(1);
}

int main(int argc, char **argv)
{
    int fd_reg = open(REGEXFILE, O_RDONLY);
    if(fd_reg < 0)
        err_quit("open regex");
    struct stat st_reg;
    stat(REGEXFILE, &st_reg);
    char *pattern = (char *)malloc(st_reg.st_size + 1);
    if(NULL == pattern)
        err_quit("malloc pattern");
    memset(pattern, 0 , st_reg.st_size + 1);
    int ret = read(fd_reg, pattern, st_reg.st_size);
    if(ret < 0)
        err_quit("read regex");
    printf("pattern:\t %s\n", pattern);
    int fd = open(FILENAME, O_RDONLY);
    if(fd < 0)
        err_quit("open html");
    struct stat st;
    stat(FILENAME, &st);
    char *str = (char *)malloc(st.st_size + 1);
    if(NULL == str)
        err_quit("malloc str");
    memset(str, 0, st.st_size + 1);
    ret = read(fd, str, st.st_size);
    if(ret < 0)
        err_quit("read html");
    regex_t preg;
    //char pattern_2[] = "\<a.*\>.*\<\/a\>";
    if(regcomp(&preg, pattern, REG_EXTENDED) < 0)
        perror("regcomp 1");

    regmatch_t pmatch[NMATCH];
    
    if((ret = regexec(&preg, str, NMATCH, pmatch, REG_NOTBOL | REG_NOTEOL)) == 0)
    {
        int i = 0;
        for(i = 0; i < NMATCH; i++)
        {
            if(pmatch[i].rm_so != -1)
            {
                write(1, str + pmatch[i].rm_so, pmatch[i].rm_eo - pmatch[i].rm_so);
                write(1, "\n", 2);
            }
        }
    }
    else
    {
        char errbuf[512];
        regerror(ret, &preg, errbuf, 512);
        printf("err:%s\n", errbuf);
    }
    free(pattern);
    free(str);
    regfree(&preg);

    return 0;
}

