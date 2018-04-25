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

#ifdef SR04I
struct list_head *get_remap_table_m(char *key)
{
    //创建head,并初始化
    struct list_head *head = (struct list_head *) malloc(sizeof (struct list_head));

    if (NULL == head)
    {
        perror("malloc");
        return head;
    }
    init_list_head(head);

    //从nvram中读取信息
    int ret = scfgmgr_getall(&nvram_data);
    if (ret < 0 || NULL == nvram_data)
    {
        printf("get nvram failed, ret=%d\n", ret);
        SAFE_FREE(head);
        return NULL;
    }
    char *remap = value_parser(key);
#ifdef PADDEBUG
    printf("%s=%s\n", key, remap);
#endif
    int i = 0;
    int cnt = 0;
    for (i = 0; i < strlen(remap); i++)
        if (remap[i] == ';')
            cnt++;
    //分割，取出，添加到链表remap_table
    printf("cnt=%d\n", cnt);
    char *str, *token;
    char *saveptr;
    for (i = 1, str = remap;; i++, str = NULL)
    {
        token = strtok_r(str, ";", &saveptr);
        if (NULL == token && i == cnt + 1)
        {
            printf("strtok_r ends\n");
            break;
        }
        remap_entry_t *entry = (remap_entry_t *) malloc(sizeof (remap_entry_t));
        if (NULL == entry)
        {
            perror("malloc");
            free_remap_table(&head);
            return NULL;
        }
        memset(entry->before, 0, LEN_IP);
        memset(entry->after, 0, LEN_IP);
        char *format = "%[^,],%[^,],%[^,]";
        char direction[16] = { 0 };
        printf("token=%s\n", token);
        int n = sscanf(token, format, direction, entry->before, entry->after);
        printf("get_remap_table_m. n=%d, direction=%s, before=%s, after=%s\n", n, direction, entry->before, entry->after);
        entry->direction = atoi(direction);
        if(proxy == HTTPS) {
            entry->session = NULL;
            pthread_mutex_init(&(entry->lock), NULL); 
        }
        list_add_tail(&(entry->list), head);
    }
    free(nvram_data);
    return head;
}

struct list_head *get_regex_table_m(char *key)
{
    struct list_head *head = (struct list_head *)malloc(sizeof(struct list_head));
    if(head == NULL)
    {
        perror("malloc");
        return head;
    }
    init_list_head(head);
    //从nvram中读取信息
    int ret = scfgmgr_getall(&nvram_data);
    if (ret < 0 || NULL == nvram_data)
    {
        printf("get nvram failed, ret=%d\n", ret);
        SAFE_FREE(head);
        return NULL;
    }
    char *http_devices = value_parser(key);
    //#ifdef PADDEBUG
    printf("%s=%s\n", key, http_devices);
    //#endif
    /* 假设条目的分割字符是,;
     * 192.168.1.9,80,(?:...);192.168.1.9,6300,(?:...);
     * ****  要求：正则表达式中不含,和;  ****
     */
    char *p, *p1;
    for(p = http_devices; p1 = strstr(p, ";") ; p = p1 + 1)
    {
        *p1 = '\0';
        char ip[LEN_IP];
        char s_port[LEN_IP];
        char pattern[LEN_PATTERN];
        char *format = "%[^,],%[^,],%s";
        int ret = sscanf(p, format, ip, s_port, pattern);
        if(ret == 3)
        {
            printf("-ip=%s\n-port=%s\n-regex=%s\n\n", ip, s_port, pattern);
            short port = (short)atoi(s_port);
            pcre2_code *re = get_compile_code((PCRE2_SPTR)pattern, 0);
            regex_entry_t *entry = (regex_entry_t *)malloc(sizeof(regex_entry_t));
            if(entry == NULL)
            {
                perror("malloc");
                free_regex_table(&head);
                return -1;
            }
            strcpy(entry->ip, ip);
            entry->port = port;
            entry->re = re;
            list_add_tail(&(entry->list), head);
        }
    }
    SAFE_FREE(http_devices);
    SAFE_FREE(nvram_data);
    if(list_empty(head))
    {
        SAFE_FREE(head);
        return NULL;
    }
    return head;
}

pcre2_code *get_general_regex(char *key)
{
    //从nvram中读取信息
    int ret = scfgmgr_getall(&nvram_data);
    if (ret < 0 || NULL == nvram_data)
    {
        printf("get nvram failed, ret=%d\n", ret);
        return NULL;
    }
    char *ge_regex = value_parser(key);
    //#ifdef PADDEBUG
    printf("%s=%s\n", key, ge_regex);
    //#endif
    pcre2_code *re = get_compile_code((PCRE2_SPTR)ge_regex, 0);
    SAFE_FREE(ge_regex);
    SAFE_FREE(nvram_data);
    return re;
}

#endif


#ifdef OpenWRT
/* 20171206-6801G-接口*/
struct list_head *get_remap_table_m(char *file)
{
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
        char *remap  = uci_lookup_option_string(ctx, s, "remap");
        char *fromip = uci_lookup_option_string(ctx, s, "fromip");
        char *toip   = uci_lookup_option_string(ctx, s, "toip");

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
                    remap_entry_t *entry = (remap_entry_t *)malloc(sizeof(remap_entry_t));
                    if(NULL == entry)
                    {
                        perror("malloc");
                        free_remap_table(&head);
                        err = 1;
                        return NULL;
                    }
                    memset(entry, 0, sizeof(remap_entry_t));
                    sprintf(entry->before, "%s%d", prefix_bfr, strt_aft + j);
                    sprintf(entry->after, "%s%d", prefix_aft, strt_aft + j);
                    entry->direction = drct;
                    printf("drct=%d, before=%s,after=%s\n", entry->direction, entry->before, entry->after);
                    list_add_tail(&(entry->list), head);
                }
                continue;
            }

            remap_entry_t *entry = (remap_entry_t *)malloc(sizeof(remap_entry_t));
            if(entry == NULL)
            {
                perror("malloc() in get remap_table");
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
    struct list_head *head = (struct list_head *)malloc(sizeof(struct list_head));
    if(head == NULL)
    {
        perror("malloc");
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
        char *ip    = uci_lookup_option_string(ctx, s, "ip");
        char *port  = uci_lookup_option_string(ctx, s, "port");
        char *regex = uci_lookup_option_string(ctx, s, "regex");

        pcre2_code *re = get_compile_code((PCRE2_SPTR)regex, 0);
        regex_entry_t *entry = (regex_entry_t *)malloc(sizeof(regex_entry_t));
        if(entry == NULL)
        {
            perror("malloc() in get regex_table");
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
    int cnt = 0;
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
        char *ge_re = uci_lookup_option_string(ctx, s, "general_regex");
        if(ge_re && cnt == 0)
            re = get_compile_code((PCRE2_SPTR)ge_re, 0);
    }
    uci_unload(ctx, pkg);
cleanup:
    uci_free_context(ctx);
    ctx = NULL;
    return re;
}
#endif



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



pcre2_code *get_re_by_host_port(struct list_head *head, char *host, short port)
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
            if(entry->session == NULL) {
                return NULL;
            }
            SSL_SESSION *session;
            pthread_mutex_lock(&(entry->lock));
            session = ssl_session_dup(entry->session, 1);
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
    struct list_head *pos;
    list_for_each(pos, head) {
        remap_entry_t *entry = list_entry(pos, remap_entry_t, list);
        if(strcmp(ip, entry->before) == 0) {
            pthread_mutex_lock(&(entry->lock));
            if(entry->session) {
#ifdef DEBUG
                printf("entry->session is not NULL = %p\n", entry->session);
#endif
                SSL_SESSION_free(entry->session);
                entry->session = NULL;
#ifdef DEBUG
                printf("after ssl_session_free, entry->session = %p\n", entry->session);
#endif
            }
            entry->session = ssl_session_dup(session, 1);
            pthread_mutex_unlock(&(entry->lock));

            if(entry->session) {
#ifdef DEBUG
                printf("new entry->session = %p, session = %p\n", entry->session, session);
#endif
                return 0;
            }
            else {
                printf("cannot set session %p\n", session);
                return -1;
            }
        }
    }
    return -1;
}

