/*
 * =====================================================================================
 *
 *       Filename:  policy.c
 *
 *    Description:  解析policy
 *
 *        Version:  1.0
 *        Created:  2018年03月20日 15时20分43秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#include "zone.h"
#include "pool.h"
#include "policy.h"
extern struct list_head *zone;
extern struct list_head *pool;

policy_t *create_init_policy()
{
#ifdef FUNC
    printf("==========start create_init_policy==========\n");
#endif
    policy_t *policy = (policy_t *)calloc(1, sizeof(policy_t));
    if(policy == NULL) {
        return NULL;
    }
    strcpy(policy->name, "-");
    policy->enable = 0;
    policy->type = POLICY_LOCAL;
    init_list_head(&(policy->proto));
    init_list_head(&(policy->src));
    init_list_head(&(policy->dst));
    policy->sports = NULL;
    policy->dports = NULL;
    policy->time = NULL;
    policy->target = TARGET_DROP;
    policy->extra = NULL;
    policy->nat_ip = NULL;
    policy->nat_port = NULL;
#ifdef FUNC
    printf("==========finish create_init_policy==========\n");
#endif
    return policy;
}

struct list_head *parse_policy_list(const char *file)
{
#ifdef FUNC
    printf("==========start parse_policy_list==========\n");
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
        const char *type      = uci_lookup_option_string(ctx, s, "type");
        const char *enable    = uci_lookup_option_string(ctx, s, "enable");
        const char *name      = uci_lookup_option_string(ctx, s, "name");
        const char *zone_src  = uci_lookup_option_string(ctx, s, "zone_src");
        const char *zone_dst  = uci_lookup_option_string(ctx, s, "zone_dst");
        const char *proto     = uci_lookup_option_string(ctx, s, "proto");
        const char *src       = uci_lookup_option_string(ctx, s, "src");
        const char *dst       = uci_lookup_option_string(ctx, s, "dst");
        const char *sports    = uci_lookup_option_string(ctx, s, "sports");
        const char *dports    = uci_lookup_option_string(ctx, s, "dports");
        const char *datestart = uci_lookup_option_string(ctx, s, "datestart");
        const char *datestop  = uci_lookup_option_string(ctx, s, "datestop");
        const char *timestart = uci_lookup_option_string(ctx, s, "timestart");
        const char *timestop  = uci_lookup_option_string(ctx, s, "timestop");
        const char *weekdays  = uci_lookup_option_string(ctx, s, "weekdays");
        const char *monthdays = uci_lookup_option_string(ctx, s, "monthdays");
        const char *timezone  = uci_lookup_option_string(ctx, s, "time[LEN_ZONE_NAME]zone");
        const char *target    = uci_lookup_option_string(ctx, s, "target");
        const char *extra     = uci_lookup_option_string(ctx, s, "extra");
        const char *nat_ip    = uci_lookup_option_string(ctx, s, "nat_ip");
        const char *nat_port  = uci_lookup_option_string(ctx, s, "nat_port");
        /*
           char *nat_ip     = uci_lookup_option_string(ctx, s, "nat_ip");
           char *nat_port     = uci_lookup_option_string(ctx, s, "nat_port");
           */
        if(!type || !zone_src) {
            continue;
        }
        printf("parse %s policy\n", type);
        if(strcmp(type, "forward") == 0 && !zone_dst) {
            printf("Must have zone_dst for 'forward' policy\n");
            continue;
        }
        if((strcmp(type, "dnat") == 0 || strcmp(type, "snat") == 0) && !nat_ip) {
            printf("Must have nat_ip for 'snat/dnat' policy\n");
            continue;
        }

        policy_t *policy = create_init_policy();

        if(name) {
            strcpy(policy->name, name);
        }
        if(enable) {
            if(strstr(enable, "1")) {
                policy->enable = 1;
            }
            else {
                policy->enable = 0;
            }
        }
        if(type) {
            if(strcmp(type, "local") == 0) {
                policy->type = POLICY_LOCAL;
            }
            else if (strcmp(type, "forward") == 0) {
                policy->type = POLICY_FORWARD;
            }
            else if(strcmp(type, "dnat") == 0) {
                policy->type = POLICY_DNAT;
            }
            else if(strcmp(type, "snat") == 0) {
                policy->type = POLICY_SNAT;
            }
        }
        if(zone_src) {
            strcpy(policy->zone_src, zone_src);
        }
        if(zone_dst) {
            strcpy(policy->zone_dst, zone_dst);
        }

        parse_ipt_proto_list(proto, &(policy->proto));
        print_ipt_proto_list(&(policy->proto));
        parse_ipt_ipaddr_list(src, &(policy->src));
        print_ipt_ipaddr_list(&(policy->src));
        parse_ipt_ipaddr_list(dst, &(policy->dst));            
        print_ipt_ipaddr_list(&(policy->dst));
        policy->time = parse_ipt_time(datestart, datestop, timestart, timestop, monthdays, weekdays, timezone);
        if(target) {
            if(strcmp(target, "accept") == 0) {
                policy->target = TARGET_ACCEPT;
            }
            else if(strcmp(target, "drop") == 0) {
                policy->target = TARGET_DROP;
            }    
            else if(strcmp(target, "reject") == 0) {
                policy->target = TARGET_REJECT;
            }
            else {
                policy->target = TARGET_DROP;
            }                   
        }
        if(sports) {
            if((policy->sports = (char *)calloc(1, strlen(sports) + 1))) {
                strcpy(policy->sports, sports);
            }
            else {
                free_policy_list(&head);
                err = 1;
                goto cleanup;
            }
        }
        if(dports) {
            if((policy->dports = (char *)calloc(1, strlen(dports) + 1))) {
                strcpy(policy->dports, dports);
            }
            else {
                free_policy_list(&head);
                err = 1;
                goto cleanup;
            }
        }
        if(extra) {
            if((policy->extra = (char *)calloc(1, strlen(extra) + 1))) {
                strcpy(policy->extra, extra);
            }
            else {
                free_policy_list(&head);
                err = 1;
                goto cleanup;
            }
        }
        if(nat_ip) {
            if((policy->nat_ip = (char *)calloc(1, strlen(nat_ip) + 1))) {
                strcpy(policy->nat_ip, nat_ip);
            }
            else {
                free_policy_list(&head);
                err = 1;
                goto cleanup;
            }
        }
        if(nat_port) {
            if((policy->nat_port = (char *)calloc(1, strlen(nat_port) + 1))) {
                strcpy(policy->nat_port, nat_port);
            }
            else {
                free_policy_list(&head);
                err = 1;
                goto cleanup;
            }
        }
        list_add_tail(&(policy->list), head);
    }
    err = 0;
cleanup:
    uci_unload(ctx, pkg);
    uci_free_context(ctx);
    ctx = NULL;
    if(err)
        SAFE_FREE(head);

#ifdef FUNC
    printf("==========stop parse_policy_list==========\n");
#endif
    return head;
}


int parse_ipt_proto_list(const char *str, struct list_head *head)
{
    /* all
     * tcp,udp,icmp
     * !tcp
     */
#ifdef FUNC
    printf("========== start parse_ipt_proto_list ===========\n");
#endif
    if(NULL == str || '\0' == *str) {
        ipt_proto_t *proto = (ipt_proto_t *)calloc(1, sizeof(ipt_proto_t));
        if(proto == NULL) {
            goto exit;
        }
        proto->reverse = 0;
        strcpy(proto->pname, PROTO_ALL);
        list_add_tail(&(proto->list), head);
        return 0;
    }
    //printf("str = %s\n", str);
    char *comma = NULL;
    char *left  = (char *)str;
    while((comma = strstr(left, ","))) {
        ipt_proto_t *proto = (ipt_proto_t *)calloc(1, sizeof(ipt_proto_t));
        if(proto == NULL) {
            goto exit;
        }
        char *excmark = NULL;
        strncpy(proto->pname, left, comma - left);
        excmark = strstr(proto->pname, "!");
        proto->reverse = excmark?1:0;
        if(excmark) {
            *excmark = BLANK_SPACE;
        }
        list_add_tail(&(proto->list), head);
        left = comma + 1; 
    }
    ipt_proto_t *proto = (ipt_proto_t *)calloc(1, sizeof(ipt_proto_t));
    if(proto == NULL) {
        goto exit;
    }
    char *excmark = NULL;
    strcpy(proto->pname, left);
    excmark = strstr(proto->pname, "!");
    proto->reverse = excmark?1:0;
    if(excmark) {
        *excmark = BLANK_SPACE;
    }
    list_add_tail(&(proto->list), head);
#ifdef FUNC
    printf("========== finish parse_ipt_proto_list ===========\n");
#endif
    return 0;

exit:
    free_ipt_proto_list(head);
    return -1;
}

int parse_ipt_ipaddr_list(const char *str, struct list_head *head)
{
    /* !192.168.1.1
     * !192.168.1.100-192.168.1.110
     * !192.168.1.1;!192.168.1.100-192.168.110
     */
    // find semico;
    // is iprange, is reverse.
#ifdef FUNC
    printf("========== start parse_ipt_ipaddr_list ===========\n");
#endif
    if(NULL == str || '\0' == *str) {
        ipt_ipaddr_t *ipaddr = (ipt_ipaddr_t *)calloc(1, sizeof(ipt_ipaddr_t));
        if(NULL == ipaddr){
            goto exit;
        }
        ipaddr->ip = (char *)calloc(1, strlen(IP_ALL)+1);
        if(NULL == ipaddr->ip) {
            goto exit;
        }
        strcpy(ipaddr->ip, IP_ALL);
        ipaddr->reverse = 0;
        ipaddr->iprange = 0;
        list_add_tail(&(ipaddr->list), head);
        return 0;
    }
    //printf("str = %s\n", str);
    char *left = (char *)str;
    char *semico = NULL;
    while((semico = strstr(left, ";"))) {
        ipt_ipaddr_t *ipaddr = (ipt_ipaddr_t *)calloc(1, sizeof(ipt_ipaddr_t));
        if(NULL == ipaddr){
            goto exit;
        }
        ipaddr->ip = (char *)calloc(1, semico-left+1);
        if(NULL == ipaddr->ip) {
            goto exit;
        }
        strncpy(ipaddr->ip, left, semico - left);
        char *excmark = strstr(ipaddr->ip, "!");
        char *cat     = strstr(ipaddr->ip, "-");
        ipaddr->reverse = excmark?1:0;
        ipaddr->iprange = cat?1:0;
        if(excmark) {
            *excmark = BLANK_SPACE;
        }
        list_add_tail(&(ipaddr->list), head);
        left = semico + 1;
    }
    ipt_ipaddr_t *ipaddr = (ipt_ipaddr_t *)calloc(1, sizeof(ipt_ipaddr_t));
    if(NULL == ipaddr){
        goto exit;
    }
    ipaddr->ip = (char *)calloc(1, strlen(left)+1);
    if(NULL == ipaddr->ip) {
        goto exit;
    }
    strcpy(ipaddr->ip, left);
    char *excmark = strstr(ipaddr->ip, "!");
    char *cat     = strstr(ipaddr->ip, "-");
    ipaddr->reverse = excmark?1:0;
    ipaddr->iprange = cat?1:0;
    if(excmark) {
        *excmark = BLANK_SPACE;
    }
    list_add_tail(&(ipaddr->list), head);
#ifdef FUNC
    printf("========== finish parse_ipt_ipaddr_list ===========\n");
#endif
    return 0;

exit:
    free_ipt_ipaddr_list(head);
    return -1;
}


void print_ipt_proto_list(struct list_head *head)
{
#ifdef FUNC
    printf("========== start print_ipt_proto_list ==========\n");
#endif
    if(NULL == head) {
        printf("proto list is NULL\n");
        return;
    }
    struct list_head *pos = NULL;
    list_for_each(pos, head) {
        ipt_proto_t *p = list_entry(pos, ipt_proto_t, list);
        printf("p->reverse = %d, p->pname = %s\n", p->reverse, p->pname);
    }
#ifdef FUNC
    printf("========== finish print_ipt_proto_list ==========\n");
#endif
}


void print_ipt_ipaddr_list(struct list_head *head)
{
#ifdef FUNC
    printf("========== start print_ipt_ipaddr_list ==========\n");
#endif
    if(NULL == head) {
        printf("ipaddr list is NULL\n");
        return;
    }
    struct list_head *pos = NULL;
    list_for_each(pos, head) {
        ipt_ipaddr_t *ip = list_entry(pos, ipt_ipaddr_t, list);
        printf("ip->iprange = %d, ip->reverse = %d, ip->ip = %s\n", ip->iprange, ip->reverse, ip->ip);
    }
#ifdef FUNC
    printf("========== finish print_ipt_ipaddr_list ==========\n");
#endif
}

ipt_time_t *parse_ipt_time(const char *datestart, const char *datestop, const char *timestart,
        const char *timestop, const char *monthdays, const char *weekdays, const char *timezone)
{
#ifdef FUNC
    printf("========== start parse_ipt_time ==========\n");
#endif
    ipt_time_t *time = (ipt_time_t *)calloc(1, sizeof(ipt_time_t));
    int has = 0;
    int err = 0;
    if(datestart) {
        has++;
        if((time->datestart = (char *)calloc(1, strlen(datestart) + 1))) {
            strcpy(time->datestart, datestart);
        }
        else {
            goto exit;
        }
    }
    if(datestop) {
        has++;
        if((time->datestop = (char *)calloc(1, strlen(datestop) + 1))) {
            strcpy(time->datestop, datestop);
        }
        else {
            err = 1; goto exit;
        }
    }
    if(timestart) {
        has++;
        if((time->timestart = (char *)calloc(1, strlen(timestart) + 1))) {
            strcpy(time->timestart, timestart);
        }
        else {
            err = 1; goto exit;
        }
    }
    if(timestop) {
        has++;
        if((time->timestop = (char *)calloc(1, strlen(timestop) + 1))) {
            strcpy(time->timestop, timestop);
        }
        else {
            err = 1; goto exit;
        }
    }
    if(monthdays) {
        has++;
        if((time->monthdays = (char *)calloc(1, strlen(monthdays) + 1))) {
            strcpy(time->monthdays, monthdays);
        }
        else {
            err = 1; goto exit;
        }
    }
    if(weekdays) {
        has++;
        if((time->weekdays = (char *)calloc(1, strlen(weekdays) + 1))) {
            strcpy(time->weekdays, weekdays);
        }
        else {
            err = 1; goto exit;
        }
    }
    if(timezone) {
        if((time->timezone = (char *)calloc(1, strlen(timezone) + 1))) {
            strcpy(time->timezone, timezone);
        }
        else {
            err = 1; goto exit;
        }
    }
exit:
    if(has == 0) {
        SAFE_FREE(time);
    }
    if(err) {
        free_ipt_time(&time);
    }
#ifdef FUNC
    printf("========== finish parse_ipt_time ==========\n");
#endif
    return time;
}


void free_policy_list(struct list_head **head)
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
        policy_t *policy = list_entry(pos, policy_t, list);
        free_ipt_proto_list(&(policy->proto));
        free_ipt_ipaddr_list(&(policy->src));
        free_ipt_ipaddr_list(&(policy->dst));
        free_ipt_time(&(policy->time));
        SAFE_FREE(policy->sports);
        SAFE_FREE(policy->dports);
        SAFE_FREE(policy->extra);
        SAFE_FREE(policy->nat_ip);
        SAFE_FREE(policy->nat_port);
        SAFE_FREE(policy);
        pos = tmp;
    }
    SAFE_FREE(*head);
}

void free_ipt_proto_list(struct list_head *head)
{
    struct list_head *pos = head->next;
    struct list_head *tmp = NULL;
    while(pos != head) {
        tmp = pos->next;
        ipt_proto_t *proto = list_entry(pos, ipt_proto_t, list);
        SAFE_FREE(proto);
        pos = tmp;
    }
}

void free_ipt_ipaddr_list(struct list_head *head)
{
    struct list_head *pos = head->next;
    struct list_head *tmp = NULL;
    while(pos != head) {
        tmp = pos->next;
        ipt_ipaddr_t *ipaddr = list_entry(pos, ipt_ipaddr_t, list);
        SAFE_FREE(ipaddr->ip);
        SAFE_FREE(ipaddr);
        pos = tmp;
    }
}

void free_ipt_time(ipt_time_t **time)
{
    SAFE_FREE((*time)->datestart);
    SAFE_FREE((*time)->datestop);
    SAFE_FREE((*time)->timestart);
    SAFE_FREE((*time)->timestop);
    SAFE_FREE((*time)->monthdays);
    SAFE_FREE((*time)->weekdays);
    SAFE_FREE((*time)->timezone);
    SAFE_FREE(*time);
}


psd_t *build_ipt_psdstr_tabs_m(struct list_head *phead, struct list_head *shead, struct list_head *dhead)
{
#ifdef FUNC
    printf("========== start build_ipt_psdstr_tabs_m ==========\n");
#endif
    int tab_len = 1 + ((list_count(phead)) * (list_count(shead)) * (list_count(dhead)));
    psd_t *tabs = (psd_t *)calloc(tab_len, sizeof(psd_t));
    tabs[tab_len - 1].psdstr   = NULL;
    tabs[tab_len - 1].withport = NO_PORTS;
    int index = 0;
    struct list_head *p;
    /* 三层循环嵌套 */
    list_for_each(p, phead) {
        ipt_proto_t *proto = list_entry(p, ipt_proto_t, list);
        struct list_head *s;
        list_for_each(s, shead) {
            ipt_ipaddr_t *src = list_entry(s, ipt_ipaddr_t, list);
            struct list_head *d;
            list_for_each(d, dhead) {
                ipt_ipaddr_t *dst = list_entry(d, ipt_ipaddr_t, list);
                int tcpudp = strcmp(proto->pname, "tcp")== 0 || strcmp(proto->pname, "udp") == 0?1:0;
                tabs[index].withport = tcpudp?WITH_PORTS:NO_PORTS;
                int pall = strcmp(proto->pname, "all")==0?1:0;
                char *src_str = build_ipt_ipaddrstr_m(src, IS_SRC);
                char *dst_str = build_ipt_ipaddrstr_m(dst, IS_DST);
                tabs[index].psdstr= (char *)calloc(1, LEN_PSD);
                if(NULL == tabs[index].psdstr) {
                    free_ipt_psdstr_tabs(&tabs);
                    printf("after free_ipt_psdstr_tabs tabs=%p\n", tabs);
                    return tabs;
                }
                char *fmt_psd = "%s%s%s%s%s";
                sprintf(tabs[index].psdstr, fmt_psd, proto->reverse?"! ":"",
                        pall?"":"-p ", pall?"":proto->pname, src_str!=NULL?src_str:"", dst_str!=NULL?dst_str:"");
                //printf("tabs[%d] = [%s]\n", index, tabs[index].psdstr);
                SAFE_FREE(src_str);
                SAFE_FREE(dst_str);
                index++;
            }
        }
    }
#ifdef FUNC
    printf("========== finish build_ipt_psdstr_tabs_m ==========\n");
#endif
    return tabs;
}


char *build_ipt_timestr_m(ipt_time_t *time)
{
    if(NULL == time) {
        return NULL;
    }
    else {
        char *t = (char *)calloc(1, LEN_IPT_TIME);
        if(NULL == t) {
            return NULL;
        }
        char *re = NULL;
        int re_mon = 0;
        int re_week = 0;
        if(time->monthdays && (re = strstr(time->monthdays, "!"))) {
            *re = BLANK_SPACE;
            re_mon = 1;
        }
        if(time->weekdays && (re = strstr(time->weekdays, "!"))) {
            *re = BLANK_SPACE;
            re_week = 1;
        }
        char *fmt = " -m time %s%s %s%s %s%s %s%s %s%s%s %s%s%s %s%s";
        sprintf(t, fmt,
                time->datestart?" --datestart ":"", time->datestart?:"",
                time->datestop?" --datestop ":""  , time->datestop?:"",
                time->timestart?" --timestart ":"", time->timestart?:"",
                time->timestart?" --timestop ":"" , time->timestop?:"",
                re_mon?" !":"", time->monthdays?" --monthdays ":"", time->monthdays?:"",
                re_week?" !":"", time->weekdays?" --weekdays ":""  , time->weekdays?:"",
                time->timezone?" --":""           , time->timezone?:"");
        return t;
    }
}


char *build_ipt_ipaddrstr_m(ipt_ipaddr_t *ipaddr, int is_src)
{
#ifdef FUNC
    printf("========== start build_ipt_ipaddrstr_m ==========\n");
#endif
    if(strcmp(ipaddr->ip, IP_ALL) == 0){
        return NULL;
    }
    //printf("is_src = %d\n", is_src);
    char *fmt_sip = " %s-s %s";
    char *fmt_dip = " %s-d %s";
    char *fmt_srange = " -m iprange %s--src-range %s";
    char *fmt_drange = " -m iprange %s--dst-range %s";
    char *ipstr = (char *)calloc(1, strlen(fmt_srange)+strlen(ipaddr->ip)+5); 
    if(NULL == ipstr) {
        printf("Can not allocate memory in build_ipt_ipaddrstr_m\n");
        return NULL;
    }
    if(ipaddr->iprange) {
        sprintf(ipstr, is_src==IS_SRC?fmt_srange:fmt_drange,
                ipaddr->reverse?"! ":"", ipaddr->ip);
    }
    else {
        sprintf(ipstr, is_src==IS_SRC?fmt_sip:fmt_dip,
                ipaddr->reverse?"! ":"", ipaddr->ip);
    }
#ifdef FUNC
    printf("========== finish build_ipt_ipaddrstr_m ==========\n");
#endif
    return ipstr;
}

char *build_ipt_portstr_m(const char *ports, int is_src)
{
#ifdef FUNC
    printf("========== start build_ipt_portstr_m ==========\n");
#endif
    if(ports == NULL) {
        return NULL;
    }
    char *fmt_port  = " --%sport %s";
    char *fmt_multi = " -m multiport --%sports %s";
    char *ipt_ports = (char *)calloc(1, strlen(ports) + strlen(fmt_multi) + 10);
    if(NULL == ipt_ports) {
        printf("Can not allocate memory in build_ipt_portstr_m\n");
        return NULL;
    }
    char *comma   = strstr(ports, ",");
    char *excmark = strstr(ports, "!");
    if(excmark) {
        *excmark = BLANK_SPACE;
    }
    sprintf(ipt_ports, comma?fmt_multi:fmt_port, is_src==IS_SRC?"s":"d", ports);
#ifdef FUNC
    printf("========== finish build_ipt_portstr_m ==========\n");
#endif
    return ipt_ports;
}


/*
 * 0 : TARGET_ACCEPT
 * 1 : TARGET_DROP
 * 2 : TARGET_REJECT
 */
char target_name_tabs[][32] = {
    {"ACCEPT"},
    {"DROP"},
    {"REJECT"}
};

char *build_ipt_targetstr_m(policy_t *policy)
{
#ifdef FUNC
    printf("========== start bulid_ipt_targetstr_m ==========\n");
#endif
    /* 方便扩展nat */
    if(policy->type < 0 || policy->type >= POLICY_ALL) {
        return NULL;
    }
    char *tar_str = (char *)calloc(1, LEN_TARGET);
    if(NULL == tar_str) {
        printf("Can not allocate memory in build_ipt_targetstr_m\n");
        return NULL;
    }
    switch(policy->type) {
        case POLICY_LOCAL:
        case POLICY_FORWARD:
            {
                sprintf(tar_str, "%s", target_name_tabs[policy->target]);
                break;
            }
        case POLICY_DNAT:
            {
                sprintf(tar_str, "DNAT --to-destination %s%s%s",
                        policy->nat_ip, policy->nat_port?":":"", policy->nat_port?:"");
                break;
            }
        case POLICY_SNAT:
            {
                /* 出口地址 */
                if(*(policy->nat_ip) == '0') {
                    zone_t *z = get_zone_by_name(policy->zone_dst, zone);
                    if(NULL == z ) {
                        SAFE_FREE(tar_str);
                        break;
                    }
                    /* 静态地址 */ 
                    if(strcmp(z->proto, "static") == 0) {
                        sprintf(tar_str, "SNAT --to-source %s%s%s", 
                            z->ipaddr, 
                            policy->nat_port?":":"", 
                            policy->nat_port?:"");
                    }
                    /* 拨号等 */
                    else {
                        sprintf(tar_str, "MASQUERADE");
                    }
                }
                /* 地址池 */
                else {
                    pool_t *p = get_pool_by_name(pool, policy->nat_ip);
                    if(NULL == p) {
                        SAFE_FREE(tar_str);
                        break;
                    }
                    sprintf(tar_str, "SNAT --to-source %s-%s%s%s", 
                            p->start, p->end,
                            policy->nat_port?":":"", 
                            policy->nat_port?:"");
                }
                break;
            }
        default:
            /* 永远不会执行default */
            printf("如果这句被打印，那么一定出现了错误，证明程序有bug\n");
            break;
    }
#ifdef FUNC
    printf("========== finish build_ipt_targetstr_m ==========\n");
#endif
    return tar_str;
}

void free_ipt_psdstr_tabs(psd_t **tabs)
{
    psd_t *psd;
    for(psd = *tabs; psd->psdstr != NULL; psd++){
        SAFE_FREE(psd->psdstr);
    }
    SAFE_FREE(*tabs);
}

void free_ipt_policy_member(ipt_policy_t *ipt_policy)
{
    free_ipt_psdstr_tabs(&(ipt_policy->psd_tabs));
    SAFE_FREE(ipt_policy->sports);
    SAFE_FREE(ipt_policy->dports);
    SAFE_FREE(ipt_policy->time);
    SAFE_FREE(ipt_policy->extra);
    SAFE_FREE(ipt_policy->target);
}


