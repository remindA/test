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
    if(argc !=2 )
    {
        printf("Usage: %s uci_name\n", argv[0]);
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
    printf("package %s\n", pkg->path);
    uci_foreach_element(&pkg->sections, e_sec)
    {
        struct uci_section *s = uci_to_section(e_sec);
        /* get section type & name */
        printf("config %s %s\n", s->type, e_sec->name);

#if 1
        struct uci_element *e_opt = NULL;
        uci_foreach_element(&(s->options), e_opt)
        {
            struct uci_option *o = uci_to_option(e_opt);
            /* get option name & value */
            if(e_opt != NULL)
                printf("\toption %s\t%s\n", e_opt->name, o->v.string);
        }
#endif
    }    

    uci_unload(ctx, pkg);
cleanup:
    uci_free_context(ctx);
    ctx = NULL;

    return 0;
}

