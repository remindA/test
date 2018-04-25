#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <uci.h>

/* 实现uci export的功能 */

int main(int argc, char **argv)
{
    if(argc !=2 )
    static struct uci_context *ctx = NULL;
    struct uci_package *pkg;
    struct uci_element *e = NULL;

    ctx = uci_alloc_context();
    if(UCI_OK != uci_load(ctx, "http_proxy_regex", &pkg))
        goto cleanup;
    uci_foreach_element(&pkg->sections, e)
    {

        struct uci_section *s = uci_to_section(e);
        char *gen_regex;
        char *server;
        char *port;
        char *regex;
        if(NULL != (gen_regex = uci_lookup_option_string(ctx, s, "general_regex")))
        {
            printf("\t\tgeneral_regex\t\t%s\n", gen_regex);
        }

        if(NULL != (server = uci_lookup_option_string(ctx, s, "ip")))
            printf("\t\tip\t\t%s\n", server);
        if(NULL != (port = uci_lookup_option_string(ctx, s, "port")))
            printf("\t\tport\t\t%s\n", port);
        if(NULL != (regex = uci_lookup_option_string(ctx, s, "regex")))
            printf("\t\tregex\t\t%s\n", regex);
        printf("\n");
    }    

    uci_unload(ctx, pkg);
cleanup:
    uci_free_context(ctx);
    ctx = NULL;

    return 0;
}

