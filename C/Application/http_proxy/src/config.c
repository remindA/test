/*
 * =====================================================================================
 *
 *       Filename:  config.c
 *
 *    Description:  获取https_proxy.cfg, remap_table, regex_table
 *
 *        Version:  1.0
 *        Created:  2018年01月10日 12时50分54秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#include "config.h"

/* 见http.c */
#include "http.h"
extern int proxy;

/* 20171206-6801G-接口*/
struct list_head *get_remap_table_m(char *file)
{
    //创建head,并初始化
    int err = 0;
    struct list_head *head = (struct list_head *) calloc(1, sizeof (struct list_head));
    if (NULL == head)
    {
        perror("calloc");
        err = 1;
        goto cleanup;
    }
    init_list_head(head);

    static struct uci_context *ctx;
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
        const char *remap  = uci_lookup_option_string(ctx, s, "remap");
        const char *fromip = uci_lookup_option_string(ctx, s, "fromip");
        const char *toip   = uci_lookup_option_string(ctx, s, "toip");

        if(remap && fromip && toip)
        {
            int drct = 0;
            if(0 == strcmp(remap, "lan2wan"))
                drct = 0;
            else if(0 == strcmp(remap, "wan2lan"))
                drct = 1;
            else
            {
                err = 1;
                free_remap_table(&head);
                goto cleanup;
            }
            if(strchr(fromip, '-') && strchr(toip, '-'))
            {

                char ip_bfr[16] = {0};
                char st_bfr[4] = {0};
                char ed_bfr[4] = {0};
                char prefix_bfr[16] = {0};
                sscanf(fromip, "%[^-]-%s", ip_bfr, ed_bfr);
                char *dot_bfr = strrchr(ip_bfr, '.');
                strcpy(st_bfr, dot_bfr + 1);
                strncpy(prefix_bfr, ip_bfr, dot_bfr - ip_bfr + 1);
                int strt_bfr = atoi(st_bfr);
                int end_bfr = atoi(ed_bfr);
                int len_bfr = end_bfr - strt_bfr + 1;

                char ip_aft[16] = {0};
                char st_aft[4] = {0};
                char ed_aft[4] = {0};
                char prefix_aft[16] = {0};
                sscanf(toip, "%[^-]-%s", ip_aft, ed_aft);
                char *dot_aft = strrchr(ip_aft, '.');
                strcpy(st_aft, dot_aft + 1);
                strncpy(prefix_aft, ip_aft, dot_aft - ip_aft + 1);
                int strt_aft = atoi(st_aft);
                int end_aft = atoi(ed_aft);
                int len_aft = end_aft - strt_aft + 1;

                if(len_bfr != len_aft)
                {
                    printf("Seg Length ERR. len_bfr = %d, len_aft = %d\n", len_bfr, len_aft);
                    free_remap_table(&head);
                    err = 1;
                    return NULL;
                }

                int j = 0;
                for(j = 0; j < len_bfr; j++)
                {
                    remap_entry_t *entry = (remap_entry_t *)calloc(1, sizeof(remap_entry_t));
                    if(NULL == entry)
                    {
                        perror("calloc");
                        free_remap_table(&head);
                        err = 1;
                        return NULL;
                    }
                    sprintf(entry->before, "%s%d", prefix_bfr, strt_aft + j);
                    sprintf(entry->after, "%s%d", prefix_aft, strt_aft + j);
                    entry->direction = drct;
                    if(proxy == HTTPS) {
                        entry->session = NULL;
                        pthread_mutex_init(&(entry->lock), NULL); 
                    }
                    printf("drct=%d, before=%s,after=%s\n", entry->direction, entry->before, entry->after);
                    list_add_tail(&(entry->list), head);
                }
                continue;
            }

            remap_entry_t *entry = (remap_entry_t *)calloc(1, sizeof(remap_entry_t));
            if(entry == NULL)
            {
                perror("calloc() in get remap_table");
                free_remap_table(&head);
                err = 1;
                goto cleanup;
            }

            strcpy(entry->before, fromip);
            strcpy(entry->after, toip);
            entry->direction = drct;
            if(proxy == HTTPS) {
                entry->session = NULL;
                pthread_mutex_init(&(entry->lock), NULL); 
            }
            printf("drct=%d, before=[%s],after=[%s]\n", entry->direction, entry->before, entry->after);
            list_add_tail(&(entry->list), head);
        }
    }
    err = 0;
cleanup:
    uci_unload(ctx, pkg);
    uci_free_context(ctx);
    ctx = NULL;
    if(err)
        SAFE_FREE(head);
    return head;
}

/* 20171206-6801G-接口*/
struct list_head *get_regex_table_m(char *file)
{
    //创建head,并初始化
    int err = 0;
    struct list_head *head = (struct list_head *)calloc(1, sizeof(struct list_head));
    if(head == NULL)
    {
        perror("calloc");
        err = 1;
        goto cleanup;
    }
    init_list_head(head);

    static struct uci_context *ctx;
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
        const char *type    = uci_lookup_option_string(ctx, s, "type");
        const char *ip    = uci_lookup_option_string(ctx, s, "ip");
        const char *port  = uci_lookup_option_string(ctx, s, "port");
        const char *regex = uci_lookup_option_string(ctx, s, "regex");
        if(!type || !ip || !port) {
            continue;
        }
        printf("type=%s, ip=%s, port=%s, regex=%s\n", type, ip, port, regex);
        pcre2_code *re = get_compile_code((PCRE2_SPTR)regex, 0);
        regex_entry_t *entry = (regex_entry_t *)calloc(1, sizeof(regex_entry_t));
        if(entry == NULL)
        {
            perror("calloc() in get regex_table");
            free_regex_table(&head);
            err = 1;
            goto cleanup;
        }
        if(ip && port)
        {
            strcpy(entry->ip, ip);
            entry->port = (short)atoi(port);
            entry->re = re;
            list_add_tail(&(entry->list), head);
        }
    }
    err = 0;
cleanup:
    uci_unload(ctx, pkg);
    uci_free_context(ctx);
    ctx = NULL;
    if(err)
        SAFE_FREE(head);
    return head;
}

/* 20171206-6801G-接口*/
pcre2_code *get_general_regex(char *file)
{
    //创建head,并初始化
    pcre2_code *re = NULL;
    static struct uci_context *ctx;
    struct uci_package *pkg;
    struct uci_element *e = NULL;

    ctx = uci_alloc_context();
    if(UCI_OK != uci_load(ctx, file, &pkg))
    {
        printf("uci_load(%s) not ok\n", file);
        goto cleanup;
    }

    uci_foreach_element(&pkg->sections, e)
    {
        struct uci_section *s = uci_to_section(e);
        const char *ge_re = uci_lookup_option_string(ctx, s, "general_regex");
        if(ge_re) {
            printf("ge_re = [%s]\n", ge_re);
            re = get_compile_code((PCRE2_SPTR)ge_re, 0);
        }    
    }
    uci_unload(ctx, pkg);
cleanup:
    uci_free_context(ctx);
    ctx = NULL;
    return re;
}

int get_http_switch(char *file)
{
    static struct uci_context *ctx;
    struct uci_package *pkg;
    struct uci_element *e = NULL;

    ctx = uci_alloc_context();
    if(UCI_OK != uci_load(ctx, file, &pkg))
    {
        printf("uci_load(%s) not ok\n", file);
        goto cleanup;
    }
    int on = 0;
    uci_foreach_element(&pkg->sections, e)
    {
        struct uci_section *s = uci_to_section(e);
        const char *http_on = uci_lookup_option_string(ctx, s, "http_on");
        if(http_on) {
            if(strcmp(http_on, "1") == 0)
                on = 1;
        }
    }
    uci_unload(ctx, pkg);
cleanup:
    uci_free_context(ctx);
    ctx = NULL;
    return on;
}


int get_https_switch(char *file)
{
    static struct uci_context *ctx;
    struct uci_package *pkg;
    struct uci_element *e = NULL;

    ctx = uci_alloc_context();
    if(UCI_OK != uci_load(ctx, file, &pkg))
    {
        printf("uci_load(%s) not ok\n", file);
        goto cleanup;
    }

    int on = 0;
    uci_foreach_element(&pkg->sections, e)
    {
        struct uci_section *s = uci_to_section(e);
        const char *https_on = uci_lookup_option_string(ctx, s, "https_on");
        if(https_on) {
            if(strcmp(https_on, "1") == 0)
                on = 1;
        }
    }
    uci_unload(ctx, pkg);
cleanup:
    uci_free_context(ctx);
    ctx = NULL;
    return on;
}


//一般不会使用此函数来释放。remap_table就是要驻留在内存中用来读取
void free_remap_table(struct list_head **head)
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
        remap_entry_t *entry = list_entry(pos, remap_entry_t, list);
        SAFE_FREE(entry);
        pos = tmp;
    }
    SAFE_FREE(*head);
}


void free_regex_table(struct list_head **head)
{
    /* 保证重复释放的安全-写代码时最好注意不要重复释放，不会访问非法内存 */
    if(*head == NULL) {
        printf("do not double free_regex_table\n");
        return;
    }
    struct list_head *pos = (*head)->next;
    struct list_head *tmp = NULL;

    while (pos != *head)
    {
        tmp = pos->next;
        regex_entry_t *entry = list_entry(pos, regex_entry_t, list);
        SAFE_FREE(entry->re);
        SAFE_FREE(entry);
        pos = tmp;
    }
    SAFE_FREE(*head);
}

pcre2_code *get_re_by_host_port(struct list_head *head, const char *host, short port)
{
#ifdef x86
    return NULL;
#endif
    if(NULL == head) {
        return NULL;
    }
    struct list_head *pos;
    list_for_each(pos, head)
    {
        regex_entry_t *entry = list_entry(pos, regex_entry_t, list);
        if(strcmp(host, entry->ip) == 0 && entry->port == port) {
            //printf("find_match re for %s:%d\n", entry->ip, entry->port);
            return entry->re;
        }
    }
    return NULL;
}

char *get_ip_before_remap(struct list_head *head, const char *ip)
{
#ifdef x86
    return ip;
#endif
    if(NULL == head) {
        return NULL;
    }
    struct list_head *pos;
    list_for_each(pos, head) {
        remap_entry_t *entry = list_entry(pos, remap_entry_t, list);
        if(strcmp(ip, entry->after) == 0) {
#ifdef DEBUG
            printf("get_ip_before_remap = %s\n", entry->before);
#endif
            return entry->before;
        }
    }
    return NULL;
}

/*
 * SSL_session_dup，所以用完需要释放
 */
SSL_SESSION *get_ssl_session(struct list_head *head, const char *ip)
{
    if(NULL == head || ip == NULL) {
        return NULL;
    }
    struct list_head *pos;
    list_for_each(pos, head) {
        remap_entry_t *entry = list_entry(pos, remap_entry_t, list);
        if(strcmp(ip, entry->before) == 0) {
#ifdef DEBUG
            printf("get_ssl_session for %s\n", ip);
#endif
            SSL_SESSION *session = NULL;
            pthread_mutex_lock(&(entry->lock));
            if(entry->session == NULL) {
                session = NULL;
            }
            else {
                session = SSL_SESSION_dup(entry->session);
            }
            pthread_mutex_unlock(&(entry->lock));
            return session;
        }
    }
    return NULL;
}


int set_ssl_session(struct list_head *head, const char *ip, SSL_SESSION *session) 
{
    if(NULL == head || session == NULL) {
        return -1;
    }
    int ret = -1;
    struct list_head *pos;
    list_for_each(pos, head) {
        remap_entry_t *entry = list_entry(pos, remap_entry_t, list);
        if(strcmp(ip, entry->before) == 0) {
            pthread_mutex_lock(&(entry->lock));
            if(entry->session) {
                SSL_SESSION_free(entry->session);
                entry->session = NULL;
            }
            entry->session = SSL_SESSION_dup(session);
            ret = entry->session?0:-1;
            pthread_mutex_unlock(&(entry->lock));
            break;
        }
    }
    
    return -1;
}

