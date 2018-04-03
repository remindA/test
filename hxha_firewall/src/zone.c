/*
 * =====================================================================================
 *
 *       Filename:  zone.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年03月20日 15时23分54秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#include "zone.h"
struct list_head *parse_zone_list(const char *file)
{
#ifdef FUNC
    printf("==========start parse_zone_list==========\n");
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
        const char *network = uci_lookup_option_string(ctx, s, "network");
#ifdef DEBUG
            printf("name = %s, network= %s\n", name, network);
#endif
        if(name && network)
        {
            zone_t *zone = (zone_t *)calloc(1, sizeof(zone_t));
            if(NULL == zone)
            {
                perror("malloc");
                err = 1;
                goto cleanup;
            }
            strcpy(zone->name, name);
            strcpy(zone->network, network);
            get_iface_by_network(zone->network, zone->iface);
#ifdef DEBUG
            printf("zone->name = %s, zone->network = %s, zone->iface = %s\n", zone->name, zone->network, zone->iface);
#endif
            list_add_tail(&(zone->list), head);
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
    printf("==========finish parse_zone_list==========\n");
#endif
    return head;
}


void free_zone_list(struct list_head **head)
{
    /* 保证重复释放的安全-写代码时最好注意不要重复释放，不会访问非法内存 */
    if(*head == NULL) {
        printf("do not double free_remap_table\n");
        return;
    }
    struct list_head *pos = (*head)->next;
    struct list_head *tmp = NULL;
    while (pos != *head)
    {
        tmp = pos->next;
        zone_t *zone = list_entry(pos, zone_t, list);
        SAFE_FREE(zone);
        pos = tmp;
    }
    SAFE_FREE(*head);
}

//char *get_iface_by_ip(const char *ip){}


int get_iface_by_network(const char *network, char *iface)
{
#ifdef FUNC
    printf("==========start get_iface_by_network==========\n");
#endif
    //创建head,并初始化
    struct uci_context *ctx;
    struct uci_package *pkg;
    struct uci_element *e = NULL;
    int find = -1;
    char *file = "network";

    ctx = uci_alloc_context();
    if(UCI_OK != uci_load(ctx, file, &pkg))
    {
        printf("uci_load(%s) not ok\n", file);
        goto cleanup;
    }
    struct uci_section *s = uci_lookup_section(ctx, pkg, network);
    if(s) {
        const char *ifname  = uci_lookup_option_string(ctx, s, "ifname");
#ifdef DEBUG
        printf("ifname = %s\n", ifname);
#endif
        if(ifname) {
            strcpy(iface, ifname);
            find = 1;
#ifdef DEBUG
        printf("iface = %s, find = %d\n", iface, find);
#endif
        }
    }
cleanup:
    uci_unload(ctx, pkg);
    uci_free_context(ctx);
    ctx = NULL;
#ifdef FUNC
    printf("==========finish get_iface_by_network==========\n");
#endif
    return find;
}


//char *get_network_by_ip(const char *ip){}
//char *get_network_by_iface(const char *iface){}
//char *get_ip_by_iface(const char *iface){}
//char *get_ip_by_network(const char *network){}

zone_t *get_zone_by_name(const char *name, struct list_head *head)
{
#ifdef FUNC
    printf("========== start get_zone_by_name ==========\n");
#endif
    zone_t *ret = NULL;
    struct list_head *pos;
    list_for_each(pos, head) {
        zone_t *zone = list_entry(pos, zone_t, list);
        if(strcmp(zone->name, name) == 0) {
            ret = zone;
            break;
        }
    }
#ifdef FUNC
            printf("========== finish get_zone_by_name ==========\n");
#endif
    return ret;
}
//zone_t *get_zone_by_network(const char *network){}
//zone_t *get_zone_by_iface(const char *iface){}
//char *get_zone_name_by_iface(const char *iface){}
//char *get_zone_name_by_network(const char *network){}
//char *get_zone_network_by_name(const char *name){}
//char *get_zone_iface_by_name(const char *name){}
