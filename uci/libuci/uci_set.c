#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <uci.h>

/* 实现uci export的功能 */
/* 
 * 显示package name
 * 显示所有section(命名和匿名的,匿名的显示匿名分配的号码)
 * 显示所有的option(list暂时不做)
 */

#define IS_OPT 0
#define IS_SEC 1

int usage(int argc, char **argv)
{
    int is_sec_opt = -1;
    if(strstr(argv[0], "uci_set_opt"))
    {
        if(argc != 5)
            printf("Usage: %s uci_name sec-name opt-name opt-value\n", argv[0]);
        else
            is_sec_opt = 0;
    }
    else if(strstr(argv[0], "uci_set_sec"))
    {
        if(argc != 4)
            printf("Usage: %s uci_name name type\n", argv[0]);
        else
            is_sec_opt = 1;
    }
    else
    {
        printf("Usage: uci_set_sec uci_name sec-name sec-type\n");
        printf("Usage: uci_set_opt uci_name sec-name opt-name opt-value\n");
    }
    return is_sec_opt;
}

/* 命令格式 uci_export uci_name */
int main(int argc, char **argv)
{
    
    int is_sec_opt = usage(argc, argv);
    if(is_sec_opt < 0)
        return 0;
    static struct uci_context *ctx = NULL;
    struct uci_package *pkg;
    struct uci_element *e_sec = NULL;

    ctx = uci_alloc_context();
    if(UCI_OK != uci_load(ctx, argv[1], &pkg))
    {
        /* use uci_perror */
        char err[128] = {0};
        sprintf(err, "uci_load(%s)", argv[1]);
        uci_perror(ctx, err);

        /* use uci_get_errorstr()*/
        char *errstr;
        uci_get_errorstr(ctx, &errstr, "uci_load");
        printf("%s\n", errstr);
        free(errstr);

        goto cleanup;
    }



    printf("package %s\n", pkg->path);
#if 0 
    uci_foreach_element(&pkg->sections, e_sec)
    {
        struct uci_section *s = uci_to_section(e_sec);
        /* 先定义再赋值,定以后必须初始化结构体为0,避免野指针 
         * 必须memset,否则会存在野指针导致uci_set出现core dump,吃了亏，gdb调试了半小时才查到问题
         *
        struct uci_ptr ptr;
        memset(&ptr, 0, sizeof(struct uci_ptr));
        ptr.p = pkg;
        ptr.s = s;
        ptr.value = argv[3];
        */
        
        struct uci_ptr ptr = {
            .p = pkg,
            .s = s,
            .value = argv[3]
        };
        
        if(is_sec)
            ptr.section = argv[2];
        
        else if(is_opt)
            ptr.option  = argv[2];

        if(0 != uci_set(ctx, &ptr))
            uci_perror(ctx, "uci_set");
    }
#endif
    struct uci_ptr ptr = {
            .p = pkg,
            .section = argv[2]
    };
        
    if(is_sec_opt == IS_SEC)
    {
        ptr.value = argv[3];
    }
    else if(is_sec_opt == IS_OPT)
    {
        ptr.option = argv[3];
        ptr.value  = argv[4];
    }

    if(0 != uci_set(ctx, &ptr))
        uci_perror(ctx, "uci_set");

    if(0 != uci_commit(ctx, &pkg, false))
        uci_perror(ctx, "uci_commit");
    uci_unload(ctx, pkg);

cleanup:
    uci_free_context(ctx);
    ctx = NULL;

    return 0;
}

