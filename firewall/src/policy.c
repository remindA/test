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

#include "policy.h"


policy_t *create_init_policy()
{
    policy_t *policy = (policy_t *)calloc(1, sizeof(policy_t));
    if(policy == NULL) {
        return NULL;
    }
    strcpy(policy->name, "-");
    policy->type = POLICY_LOCAL;
    policy->zone_src = NULL;
    policy->zone_dst = NULL;
    init_list_head(&(policy->proto));
    init_list_head(&(policy->src));
    init_list_head(&(policy->dst));
    policy->sports = NULL;
    policy->dports = NULL;
    memset(&(policy->time), 0, sizeof(ipt_time_t));
    policy->target = TARGET_DROP;
    policy->extra = NULL;
    /*
       policy->nat_ip = NULL;
       policy->nat_port = NULL;
       */
    return policy;
}

struct list_head *parse_policy_list(const char *file, struct list_head *zhead);
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
        char *type      = uci_lookup_option_string(ctx, s, "type");
        char *name      = uci_lookup_option_string(ctx, s, "name");
        char *zone_src  = uci_lookup_option_string(ctx, s, "zone_src");
        char *zone_dst  = uci_lookup_option_string(ctx, s, "zone_dst");
        char *proto     = uci_lookup_option_string(ctx, s, "proto");
        char *src       = uci_lookup_option_string(ctx, s, "src");
        char *dst       = uci_lookup_option_string(ctx, s, "dst");
        char *sports    = uci_lookup_option_string(ctx, s, "sports");
        char *dports    = uci_lookup_option_string(ctx, s, "dports");
        char *datestart = uci_lookup_option_string(ctx, s, "datestart");
        char *datestop  = uci_lookup_option_string(ctx, s, "datestop");
        char *timestart = uci_lookup_option_string(ctx, s, "timestart");
        char *timestop  = uci_lookup_option_string(ctx, s, "timestop");
        char *weekdays  = uci_lookup_option_string(ctx, s, "weekdays");
        char *monthdays = uci_lookup_option_string(ctx, s, "monthdays");
        char *timezone  = uci_lookup_option_string(ctx, s, "time[LEN_ZONE_NAME]zone");
        char *target    = uci_lookup_option_string(ctx, s, "target");
        char *extra     = uci_lookup_option_string(ctx, s, "extra");
        /*
           char *nat_ip     = uci_lookup_option_string(ctx, s, "nat_ip");
           char *nat_port     = uci_lookup_option_string(ctx, s, "nat_port");
           */
        if(!type || !zone_src) {
            continue;
        }
        if(strcmp(type, "forward") == 0 && !zone_dst) {
            continue;
        }

        policy_t *policy = create_init_policy();

        if(name) {
            strcpy(policy->name, name);
        }
        if(type) {
            if(strcmp(type, "local") == 0) {
                policy->type = POLICY_LOCAL;
            }
            else if (strcmp(type, "forward") == 0) {
                policy->type = POLICY_FORWARD;
            }
        }
        if(zone_src) {
            strcpy(policy->zone_src, zone_src);
        }
        if(zone_dst) {
            strcpy(policy->zone_dst, zone_dst);
        }

        if(proto) {
            parse_ipt_proto_list(proto, &(policy->proto));
        }
        if(src) {
            parse_ipt_ipaddr_list(src, &(policy->src));
        }
        if(dst) {
            parse_ipt_ipaddr_list(dst, &(policy->dst));            
        }
        parse_ipt_time(datestart, datestop, timestart, timestop, monthdays, weekdays, timezone, &(policy->time));
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
        list_add_tail(&(zone->list), head);
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


int parse_ipt_proto_list(const char *str, struct list_head *head)
{
    /* all
     * tcp,udp,icmp
     * !tcp
     */
    if(NULL == str || *str = '\0') {
        printf("arg wrong\n");
        return -1;
    }
    char *comma = NULL;
    char *left  = str;
    while((comma = strstr(left, ","))) {
        ipt_proto_t *proto = (ipt_proto_t *)calloc(1, sizeof(ipt_proto_t));
        if(proto == NULL) {
            goto exit;
        }
        char *excmark = NULL:
            strncpy(proto->pname, left, comma - left);
        excmark = strstr(proto->pname, "!")?1:0;
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
    char *excmark = NULL:
        strcpy(proto->pname, left);
    excmark = strstr(proto->pname, "!")?1:0;
    proto->reverse = excmark?1:0;
    if(excmark) {
        *excmark = BLANK_SPACE;
    }
    list_add_tail(&(proto->list), head);
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
    if(NULL == str || *str = '\0') {
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
    char *left = str;
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
    return 0;

exit:
    free_ipt_ipaddr_list(head);
    return -1;
}

ipt_time_t *parse_ipt_time(const char *datestart, const char *datestop, const char *timestart,
        const char *timestop, const char *monthdays, const char *weekdays, const char *timezone)
{
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
        /*
           SAFE_FREE(policy->nat_ip);
           SAFE_FREE(policy->nat_port);
           */
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

void free_ipt_time(ipt_time_t **time) {
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
    int tab_len = 1 + list_count(phead) * list_count(shead) * list_count(dhead);
    psd_t tabs = (psd_t *)calloc(tab_len, sizeof(psd_t));
    tabs[tab_len - 1] = {NO_PORTS, NULL};
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
                tabs[index].withport = tcpudp?NO_PORTS:WITH_PORTS;
                int pall = strcmp(proto->pname, "all")==0?1:0;
                char *src_str = build_ipt_ipaddrstr_m(src, IS_SRC);
                char *dst_str = build_ipt_ipaddrstr_m(dst, IS_DST);
                tabs[index].psdtr= (char *)calloc(1, 1 + strlen(proto->pname)
                        + strlen(src_str?:"")
                        + strlen(dst_str?:""));
                if(NULL == tabs[index].psdstr) {
                    free_ipt_psdstr_tabs(&tabs);
                    printf("after free_ipt_psdstr_tabs tabs=%p\n", tabs);
                    return tabs;
                }
                char *fmt_psd = "%s%s%s %s %s";
                sprintf(tabs[index].psdstr, fmt_psd, proto->reverse?"! ":"",
                        pall?"":"-p ", pall?"":proto->pname, src_str, dst_str);
            }
        }
    }
    return tabs;
}


char *build_ipt_timestr_m(ipt_time_t *time) {
    if(NULL == time) {
        return NULL;
    }
    else {
        char *t = (char *)calloc(1, LEN_IPT_TIME);
        if(NULL == t) {
            return NULL;
        }
        char *fmt = "-m time %s%s %s%s %s%s %s%s %s%s %s%s %s%s";
        sprintf(t, fmt,
                time->datestart?"--datestart ":"", time->datestart?:"",
                time->datestop?"--datestop ":""  , time->datestop?:"",
                time->timestart?"--timestart ":"", time->timestart?:"",
                time->timestart?"--timestop ":"" , time->timestop?:"",
                time->monthdays?"--monthdays ":"", time->monthdays?:"",
                time->weekdays?"--weekdays ":""  , time->weekdays?:"",
                time->timezone?"--":""           , time->timezone?:"");
        return t;
    }
}


char *build_ipt_ipaddrstr_m(ipt_ipaddr_t *ipaddr, int is_src)
{
    if(strcmp(ipaddr->ip, IP_ALL) == 0){
        return NULL;
    }
    char *fmt_sip = "%s-s %s";
    char *fmt_dip = "%s-d %s";
    char *fmt_srange = "-m iprange %s--src-range %s";
    char *fmt_drange = "-m iprange %s--dst-range %s";
    char *ipstr = (char *)calloc(1, strlen(fmt_srange)+strlen(ipaddr->ip)+5); 
    if(NULL == ipstr) {
        printf("Can not allocate memory in build_ipt_ipaddrstr_m\n");
        return NULL;
    }
    if(ipaddr->iprange) {
        sprinf(ipstr, is_src?fmt_srange:fmt_drange,
                ipaddr->reverse?"! ":"", ipaddr->ip);
    }
    else {
        sprintf(ipstr, is_src?fmt_sip:fmt_dip,
                ipaddr->reverse?"! ":"", ipaddr->ip);
    }
    return ipstr;
}

char *build_ipt_portstr_m(const char *ports, int is_src)
{
    if(ports == NULL) {
        return NULL;
    }
    char *fmt_port  = "--%sport %s";
    char *fmt_multi = "-m multiport --%sports %s"
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
    sprintf(ipt_ports, comma?fmt_multi:fmt_port, is_src?"s":"d", ports);
    return ipt_ports;
}

char *build_ipt_targetstr_m(policy_t *policy)
{
    /* 方便扩展nat */
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
            /*
               case POLICY_DNAT:
               case POLICY_SNAT:
               {
               char *nataddr = build_ipt_nataddrstr_m(policy->type, policy->nat_ip, policy->nat_port);
               sprintf(tar_str, "%s %s", target_name_tabs[policy->target], nataddr);
               SAFE_FREE(nataddr);
               break;
               }
               */
        default:
            SAFE_FREE(tar_str);
            break;
    }
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

void free_ipt_policy_member(ipt_policy_t *ipt_policy) {
    free_ipt_psdstr_tabs(ipt_policy->psd_tabs);
    SAFE_FREE(ipt_policy->sports);
    SAFE_FREE(ipt_policy->dports);
    SAFE_FREE(ipt_policy->time);
    SAFE_FREE(ipt_policy->extra);
    SAFE_FREE(ipt_policy->target);
}


#define new_ipt_policy(policy) \
{   policy->type,\
    build_ipt_psdstr_tabs_m(&(policy->proto), &(policy->src), &(policy->dst)),\
    build_ipt_portstr_m(policy->sports, IS_SRC),\
    build_ipt_portstr_m(policy->dports, IS_DST),\
    build_ipt_timestr_m(policy->time),\
    policy->extra,\
    build_ipt_targetstr_m(policy)\
}


void ipt_init_print()
{
    printf("iptables -t filter -P INPUT DROP");
    printf("iptables -t filter -P OUTPUT DROP");
    printf("iptables -t filter -P FORWARD DROP");

    printf("iptables -t nat    -F PREROUTING");
    printf("iptables -t nat    -F POSTROUTING");
    printf("iptables -t filter -F INPUT");
    printf("iptables -t filter -F OUTPUT");
    printf("iptables -t filter -F FORWARD");

    printf("iptables -t nat    -X dispatch_prerouting");
    printf("iptables -t nat    -X dispatch_postrouting");
    printf("iptables -t filter -X dispatch_input");
    printf("iptables -t filter -X dispatch_output");
    printf("iptables -t filter -X dispatch_forward");
    printf("iptables -t nat    -N dispatch_prerouting");
    printf("iptables -t nat    -N dispatch_postrouting");
    printf("iptables -t filter -N dispatch_input");
    printf("iptables -t filter -N dispatch_output");
    printf("iptables -t filter -N dispatch_forward");

    printf("iptables -t nat    -A PREROUTING  -j dispatch_prerouting");
    printf("iptables -t nat    -A POSTROUTING -j dispatch_postrouting");
    printf("iptables -t filter -A INPUT   -j dispatch_input");
    printf("iptables -t filter -A OUTPUT  -j dispatch_output");
    printf("iptables -t filter -A FORWARD -j dispatch_forward");
}


void ipt_zone_print(struct list_head *head)
{
    struct list_head *pos;
    list_for_each(pos, head) {
        zone_t *zone = list_entry(pos, zone_t, list);
        printf("iptables -t nat    -N %s_prerouting", zone->name);
        printf("iptables -t nat    -N %s_postrouting", zone->name);
        printf("iptables -t filter -N %s_input", zone->name);
        printf("iptables -t filter -N %s_output", zone->name);
        printf("iptables -t filter -N %s_forward", zone->name);
        printf("iptables -t nat    -A dispatch_prerouting -i %s -j %s_prerouting", zone->iface, zone->name);
        printf("iptables -t nat    -A dispatch_postrouting -o %s -j %s_postrouting", zone->iface, zone->name);
        printf("iptables -t filter -A dispatch_input -i %s -j %s_input", zone->iface, zone->name);
        printf("iptables -t filter -A dispatch_output -o %s -j %s_output", zone->iface, zone->name);
        printf("iptables -t filter -A dispatch_forward -i %s -j %s_forward", zone->iface, zone->name);
    }
}

void ipt_policy_print(struct list_head *head)
{
    struct list_head *pos;
    list_for_each(pos, head) {
        policy_t *policy = list_entry(pos, policy_t, list);
        ipt_policy_t ipt_policy = new_ipt_policy(policy);
        switch(ipt_p.type){
            case POLICY_LOCAL:
                {
                    psd_t *psd;
                    for(psd = ipt_policy.psd_tabs; psd->psdstr != NULL; psd++){
                        printf("iptables -t filter -A %s_input %s %s %s %s -j %s", 
                                policy->zone_src, 
                                psd->psdstr,
                                psd->withport?ipt_policy.sports:"",
                                psd->withport?ipt_policy.dports:"",
                                ipt_policy.extra?:"",
                                ipt_policy.target?:"DROP");
                    }
                    /* 回应包全部转发 */
                    printf("iptables -t filter -A %s_output -m state --state ESTABLISHED,RELATED -j ACCEPT", policy->zone_src);
                    break;
                }
            case POLICY_FORWARD:
                {
                    psd_t *psd;
                    for(psd = ipt_policy.psd_tabs; psd->psdstr != NULL; psd++){
                        printf("iptables -t filter -A %s_forward %s %s %s %s -j %s", 
                                policy->zone_src, 
                                psd->psdstr,
                                psd->withport?ipt_policy.sports:"",
                                psd->withport?ipt_policy.dports:"",
                                ipt_policy.extra?:"",
                                ipt_policy.target?:"DROP");
                    }
                    /* 回应包全部转发 */
                    printf("iptables -t filter -A %s_forward -m state --state ESTABLISHED,RELATED -j ACCEPT", policy->zone_dst);
                }
        }
        free_ipt_policy_member(&ipt_policy);
    }
}
