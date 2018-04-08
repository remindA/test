/*
 * =====================================================================================
 *
 *       Filename:  pool.c
 *
 *    Description:  snat_pool
 *
 *        Version:  1.0
 *        Created:  2018年04月08日 13时46分04秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#include "pool.h"

struct list_head *parse_pool_list(const char *file)
{
#ifdef FUNC
    printf("==========start parse_pool_list==========\n");
#endif
    //创建head,并初始化
    int err = 0;
    struct list_head *head = (struct list_head *) malloc(sizeof (struct list_head));
    if (NULL == head)
    {
        perror("malloc");
        err = 1;
        goto cleanup;
    }
    init_list_head(head);

    struct uci_context *ctx;
    struct uci_package *pkg;
    struct uci_element *e = NULL;

    ctx = uci_alloc_context();
    if(UCI_OK != uci_load(ctx, file, &pkg))
    {
        printf("uci_load(%s) not ok\n", file);
        err = 1;
        goto cleanup;
    }

    uci_foreach_element(&pkg->sections, e)
    {
        struct uci_section *s = uci_to_section(e);
        const char *name  = uci_lookup_option_string(ctx, s, "name");
        const char *start = uci_lookup_option_string(ctx, s, "start");
        const char *end   = uci_lookup_option_string(ctx, s, "end");
        if(name && start && end)
        {
            pool_t *pool = (pool_t *)calloc(1, sizeof(pool_t));
            if(NULL == pool)
            {
                perror("malloc");
                err = 1;
                goto cleanup;
            }
            strcpy(pool->name, name);
            strcpy(pool->start, start);
            strcpy(pool->end, end);
            list_add_tail(&(pool->list), head);
        }
    }
    err = 0;
cleanup:
    uci_unload(ctx, pkg);
    uci_free_context(ctx);
    ctx = NULL;
    if(err)
        SAFE_FREE(head);

#ifdef FUNC
    printf("==========finish parse_pool_list==========\n");
#endif
    return head;
}


void free_pool_list(struct list_head **head)
{
    /* 保证重复释放的安全-写代码时最好注意不要重复释放，不会访问非法内存 */
    if(*head == NULL) {
        printf("do not double pool list\n");
        return;
    }
    struct list_head *pos = (*head)->next;
    struct list_head *tmp = NULL;
    while (pos != *head)
    {
        tmp = pos->next;
        pool_t *pool = list_entry(pos, pool_t, list);
        SAFE_FREE(pool);
        pos = tmp;
    }
    SAFE_FREE(*head);
}

pool_t *get_pool_by_name(struct list_head *head, const char *name)
{
    struct list_head *pos;
    list_for_each(pos, head) {
        pool_t *p = list_entry(pos, pool_t, list);
        if(strcmp(name, p->name) == 0) {
            return p;
        }
    }
    return NULL;
}
