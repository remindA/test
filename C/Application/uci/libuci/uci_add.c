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

/* 命令格式 uci_export uci_name */
int main(int argc, char **argv)
{
    if(argc !=4)
    {
        printf("Usage: %s uci_name opt-name opt-value\n", argv[0]);
        return 0;
    }
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

    //char *type = argv[2];
    printf("package %s\n", pkg->path);
    uci_foreach_element(&pkg->sections, e_sec)
    {
        struct uci_section *s = uci_to_section(e_sec);
        /* 修改option的value 或者 新增option及其value */
        struct uci_ptr ptr = {
            .p = pkg,
            .s = s,
            .option = argv[2],
            .value  = argv[3]
        };
        if(0 != uci_set(ctx, &ptr))
            uci_perror(ctx, "uci_set");
    }
    if(0 != uci_commit(ctx, &pkg, false))
        uci_perror(ctx, "uci_commit");
    uci_unload(ctx, pkg);

cleanup:
    uci_free_context(ctx);
    ctx = NULL;

    return 0;
}

