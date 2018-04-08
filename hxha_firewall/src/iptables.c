/*
 * =====================================================================================
 *
 *       Filename:  iptables.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年03月30日 11时35分34秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#include "iptables.h"


void ipt_init_print(void)
{
    printf("========== ipt_init_print ==========\n");
    printf("iptables -t filter -P INPUT DROP\n");
    printf("iptables -t filter -P OUTPUT DROP\n");
    printf("iptables -t filter -P FORWARD DROP\n");

    printf("iptables -t nat    -F PREROUTING\n");
    printf("iptables -t nat    -F POSTROUTING\n");
    printf("iptables -t filter -F INPUT\n");
    printf("iptables -t filter -F OUTPUT\n");
    printf("iptables -t filter -F FORWARD\n");

    printf("iptables -t nat    -X dispatch_prerouting\n");
    printf("iptables -t nat    -X dispatch_postrouting\n");
    printf("iptables -t filter -X dispatch_input\n");
    printf("iptables -t filter -X dispatch_output\n");
    printf("iptables -t filter -X dispatch_forward\n");
    printf("iptables -t nat    -N dispatch_prerouting\n");
    printf("iptables -t nat    -N dispatch_postrouting\n");
    printf("iptables -t filter -N dispatch_input\n");
    printf("iptables -t filter -N dispatch_output\n");
    printf("iptables -t filter -N dispatch_forward\n");

    printf("iptables -t nat    -A PREROUTING  -j dispatch_prerouting\n");
    printf("iptables -t nat    -A POSTROUTING -j dispatch_postrouting\n");
    printf("iptables -t filter -A INPUT   -j dispatch_input\n");
    printf("iptables -t filter -A OUTPUT  -j dispatch_output\n");
    printf("iptables -t filter -A FORWARD -j dispatch_forward\n");
}


void ipt_zone_print(struct list_head *head)
{
    printf("========== ipt_zone_print ==========\n");
    struct list_head *pos;
    list_for_each(pos, head) {
        zone_t *zone = list_entry(pos, zone_t, list);
        printf("iptables -t nat    -N %s_prerouting\n", zone->name);
        printf("iptables -t nat    -N %s_postrouting\n", zone->name);
        printf("iptables -t filter -N %s_input\n", zone->name);
        printf("iptables -t filter -N %s_output\n", zone->name);
        printf("iptables -t filter -N %s_forward\n", zone->name);
        printf("iptables -t nat    -A dispatch_prerouting -i %s -j %s_prerouting\n", zone->iface, zone->name);
        printf("iptables -t nat    -A dispatch_postrouting -o %s -j %s_postrouting\n", zone->iface, zone->name);
        printf("iptables -t filter -A dispatch_input -i %s -j %s_input\n", zone->iface, zone->name);
        printf("iptables -t filter -A dispatch_output -o %s -j %s_output\n", zone->iface, zone->name);
        printf("iptables -t filter -A dispatch_forward -i %s -j %s_forward\n", zone->iface, zone->name);
    }
}

policy_print print_fun_tabs[] = {
    ipt_policy_local_print,
    ipt_policy_forward_print,
    ipt_policy_dnat_print,
    ipt_policy_snat_print
};

void ipt_policy_print(struct list_head *head, int type)
{
    /* type还没使用 */
    printf("========== ipt_policy_print (%d)==========\n", type);
    struct list_head *pos;
    list_for_each(pos, head) {
        policy_t *policy = list_entry(pos, policy_t, list);
        if(type != POLICY_ALL && type == policy->type) {
            print_fun_tabs[policy->type](policy);
            continue;
        }
        print_fun_tabs[policy->type](policy);
    }
}

void ipt_policy_local_print(policy_t *policy)
{
    ipt_policy_t ipt_policy = new_ipt_policy(policy);
    psd_t *psd;
    for(psd = ipt_policy.psd_tabs; psd->psdstr != NULL; psd++){
        printf("iptables -t filter -A %s_input %s%s%s %s -j %s\n", 
                policy->zone_src, 
                psd->psdstr,
                psd->withport&&ipt_policy.sports?ipt_policy.sports:"",
                psd->withport&&ipt_policy.dports?ipt_policy.dports:"",
                ipt_policy.extra?:"",
                ipt_policy.target?:"DROP");
    }
    /* 回应包全部转发 */
    printf("iptables -t filter -A %s_output -m state --state ESTABLISHED,RELATED -j ACCEPT\n", policy->zone_src);
    free_ipt_policy_member(&ipt_policy);
}

void ipt_policy_forward_print(policy_t *policy)
{
    ipt_policy_t ipt_policy = new_ipt_policy(policy);
    psd_t *psd;
    for(psd = ipt_policy.psd_tabs; psd->psdstr != NULL; psd++){
        printf("iptables -t filter -A %s_forward %s%s%s%s -j %s\n", 
                policy->zone_src, 
                psd->psdstr,
                psd->withport&&ipt_policy.sports?ipt_policy.sports:"",
                psd->withport&&ipt_policy.dports?ipt_policy.dports:"",
                ipt_policy.extra?:"",
                ipt_policy.target?:"DROP");
    }
    /* 回应包全部转发 */
    printf("iptables -t filter -A %s_forward -m state --state ESTABLISHED,RELATED -j ACCEPT\n", policy->zone_dst);
    free_ipt_policy_member(&ipt_policy);
}


void ipt_policy_snat_print(policy_t *policy)
{

}


void ipt_policy_dnat_print(policy_t *policy)
{

}

int make_fw_run_script(char *file, struct list_head *zhead, struct list_head *phead)
{
    int fd = open(file, O_WRONLY | O_TRUNC | O_CREAT, 0777);
    if(fd < 0) {
        perror("make_fw_run_script open");
        return fd;
    }
    int ret = -1;
    ret = write_iptables_init(fd);
    ret = write_iptables_zone(fd, zhead);
    ret = write_iptables_policy(fd, phead);
    close(fd);
    return ret;
}


int make_fw_flush_script(char *file, struct list_head *zhead)
{
    /* 解引用，清空，删除 */
    int fd = open(file, O_WRONLY | O_TRUNC | O_CREAT, 0777);
    if(fd < 0) {
        perror("make_fw_flush_script open");
        return fd;
    }

    int ret;
    /* 解引用自定义链 */
    const char *custom = 
    "#!/bin/sh\n"
    "echo '===== 解引用自定义链 ====='\n"
    "iptables -t nat    -F dispatch_prerouting\n"
    "iptables -t nat    -F dispatch_postrouting\n"
    "iptables -t filter -F dispatch_input\n"
    "iptables -t filter -F dispatch_output\n"
    "iptables -t filter -F dispatch_forward\n"
    "echo '===== 清空自定义链并删除 ====='\n";
    ret = my_write(fd, custom, strlen(custom));
    char buff[LEN_CMD] = {0};
    struct list_head *pos;
    list_for_each(pos, zhead) {
        /* 清空自定义链中的所有规则,并删除 */
        zone_t *zone = list_entry(pos, zone_t, list);
        memset(buff, 0, sizeof(buff));
        sprintf(buff, "iptables -t nat    -F %s_prerouting\n""iptables -t nat    -X %s_prerouting\n", zone->name, zone->name);
        my_write(fd, buff, strlen(buff));

        memset(buff, 0, sizeof(buff));
        sprintf(buff, "iptables -t nat    -F %s_postrouting\n""iptables -t nat    -X %s_postrouting\n", zone->name, zone->name);
        my_write(fd, buff, strlen(buff));

        memset(buff, 0, sizeof(buff));
        sprintf(buff, "iptables -t filter -F %s_input\n""iptables -t filter -X %s_input\n", zone->name, zone->name);
        my_write(fd, buff, strlen(buff));

        memset(buff, 0, sizeof(buff));
        sprintf(buff, "iptables -t filter -F %s_output\n""iptables -t filter -X %s_output\n", zone->name, zone->name);
        my_write(fd, buff, strlen(buff));

        memset(buff, 0, sizeof(buff));
        sprintf(buff, "iptables -t filter -F %s_forward\n""iptables -t filter -X %s_forward\n", zone->name, zone->name);
        my_write(fd, buff, strlen(buff));
    }


    /* 解引用dispath，清空并删除 */
    const char *dispatcher = 
    "echo '===== 解引用dispatch并删除 ====='\n"
    "iptables -t nat    -F PREROUTING\n"
    "iptables -t nat    -F POSTROUTING\n"
    "iptables -t filter -F INPUT\n"
    "iptables -t filter -F OUTPUT\n"
    "iptables -t filter -F FORWARD\n"
    "iptables -t nat    -F dispatch_prerouting\n"
    "iptables -t nat    -F dispatch_postrouting\n"
    "iptables -t filter -F dispatch_input\n"
    "iptables -t filter -F dispatch_output\n"
    "iptables -t filter -F dispatch_forward\n"
    "iptables -t nat    -X dispatch_prerouting\n"
    "iptables -t nat    -X dispatch_postrouting\n"
    "iptables -t filter -X dispatch_input\n"
    "iptables -t filter -X dispatch_output\n"
    "iptables -t filter -X dispatch_forward\n";
    ret = my_write(fd, dispatcher, strlen(dispatcher));
    close(fd);
    return ret;
}


int write_iptables_init(int fd)
{
    const char *str = 
    "#!/bin/sh\n"
    "echo '===== iptables初始化 ====='\n"
    "iptables -t filter -P INPUT DROP\n"
    "iptables -t filter -P OUTPUT DROP\n"
    "iptables -t filter -P FORWARD DROP\n"
    "iptables -t nat    -F PREROUTING\n"
    "iptables -t nat    -F POSTROUTING\n"
    "iptables -t filter -F INPUT\n"
    "iptables -t filter -F OUTPUT\n"
    "iptables -t filter -F FORWARD\n"
    "echo '===== 建立dispather并引用 ====='\n"
    "iptables -t nat    -X dispatch_prerouting\n"
    "iptables -t nat    -X dispatch_postrouting\n"
    "iptables -t filter -X dispatch_input\n"
    "iptables -t filter -X dispatch_output\n"
    "iptables -t filter -X dispatch_forward\n"
    "iptables -t nat    -N dispatch_prerouting\n"
    "iptables -t nat    -N dispatch_postrouting\n"
    "iptables -t filter -N dispatch_input\n"
    "iptables -t filter -N dispatch_output\n"
    "iptables -t filter -N dispatch_forward\n"
    "iptables -t nat    -A PREROUTING  -j dispatch_prerouting\n"
    "iptables -t nat    -A POSTROUTING -j dispatch_postrouting\n"
    "iptables -t filter -A INPUT   -j dispatch_input\n"
    "iptables -t filter -A OUTPUT  -j dispatch_output\n"
    "iptables -t filter -A FORWARD -j dispatch_forward\n";
    return my_write(fd, str, strlen(str));
}

ssize_t my_write(int fd, const void *buf, size_t count)
{
    int ret = write(fd, buf, count);
    if(ret < 0) {
        perror("write");
    }
    return ret;
}

int write_iptables_zone(int fd, struct list_head *head)
{
    int ret;
    char buff[LEN_CMD] = "echo '===== 建立自定义链并引用 ====='\n";
    my_write(fd, buff, strlen(buff));
    struct list_head *pos;
    list_for_each(pos, head) {
        zone_t *zone = list_entry(pos, zone_t, list);
        memset(buff, 0, sizeof(buff));
        sprintf(buff, "iptables -t nat    -N %s_prerouting\n", zone->name);
        my_write(fd, buff, strlen(buff));

        memset(buff, 0, sizeof(buff));
        sprintf(buff, "iptables -t nat    -N %s_postrouting\n", zone->name);
        my_write(fd, buff, strlen(buff));

        memset(buff, 0, sizeof(buff));
        sprintf(buff, "iptables -t filter -N %s_input\n", zone->name);
        my_write(fd, buff, strlen(buff));

        memset(buff, 0, sizeof(buff));
        sprintf(buff, "iptables -t filter -N %s_output\n", zone->name);
        my_write(fd, buff, strlen(buff));

        memset(buff, 0, sizeof(buff));
        sprintf(buff, "iptables -t filter -N %s_forward\n", zone->name);
        my_write(fd, buff, strlen(buff));

        memset(buff, 0, sizeof(buff));
        sprintf(buff, "iptables -t nat    -A dispatch_prerouting -i %s -j %s_prerouting\n", zone->iface, zone->name);
        my_write(fd, buff, strlen(buff));

        memset(buff, 0, sizeof(buff));
        sprintf(buff, "iptables -t nat    -A dispatch_postrouting -o %s -j %s_postrouting\n", zone->iface, zone->name);
        my_write(fd, buff, strlen(buff));

        memset(buff, 0, sizeof(buff));
        sprintf(buff, "iptables -t filter -A dispatch_input -i %s -j %s_input\n", zone->iface, zone->name);
        my_write(fd, buff, strlen(buff));

        memset(buff, 0, sizeof(buff));
        sprintf(buff, "iptables -t filter -A dispatch_output -o %s -j %s_output\n", zone->iface, zone->name);
        my_write(fd, buff, strlen(buff));

        memset(buff, 0, sizeof(buff));
        sprintf(buff, "iptables -t filter -A dispatch_forward -i %s -j %s_forward\n", zone->iface, zone->name);
        my_write(fd, buff, strlen(buff));
        /* output回应包全部转发 */
        memset(buff, 0, sizeof(buff));
        sprintf(buff, "iptables -t filter -A %s_output -m state --state ESTABLISHED,RELATED -j ACCEPT\n", zone->name);
        ret = my_write(fd, buff, strlen(buff));
        /* forward回应包全部转发 */
        memset(buff, 0, sizeof(buff));
        sprintf(buff, "iptables -t filter -A %s_forward -m state --state ESTABLISHED,RELATED -j ACCEPT\n", zone->name);
        ret = my_write(fd, buff, strlen(buff));
    }
    
}

int write_iptables_policy(int fd, struct list_head *head)
{
    char buff[LEN_CMD] = "echo '===== 策略 ====='\n";
    my_write(fd, buff, strlen(buff));
    int ret = -1;
    struct list_head *pos;
    list_for_each(pos, head) {
        policy_t *policy = list_entry(pos, policy_t, list);
        printf("write_policy %d\n", policy->type);
        if(POLICY_LOCAL == policy->type) {
            ret = write_iptables_local(fd, policy);
        }
        if(POLICY_FORWARD == policy->type) {
            ret = write_iptables_forward(fd, policy);
        }
        if(POLICY_DNAT == policy->type) {
            ret = write_iptables_dnat(fd, policy);
        }
        if(POLICY_SNAT == policy->type) {
            ret = write_iptables_snat(fd, policy);
        }
    }
    return ret;
}

int write_iptables_local(int fd, policy_t *policy)
{
    if(!policy->enable) {
        return 0;
    }
    ipt_policy_t ipt_policy = new_ipt_policy(policy);
    int ret;
    psd_t *psd;
    char buff[LEN_CMD] = {0};
    for(psd = ipt_policy.psd_tabs; psd->psdstr != NULL; psd++){
        memset(buff, 0, sizeof(buff));
        sprintf(buff, "iptables -t filter -A %s_input %s%s%s %s -j %s\n", 
                policy->zone_src, 
                psd->psdstr,
                psd->withport&&ipt_policy.sports?ipt_policy.sports:"",
                psd->withport&&ipt_policy.dports?ipt_policy.dports:"",
                ipt_policy.extra?:"",
                ipt_policy.target?:"DROP");
        ret = my_write(fd, buff, strlen(buff));
    }
    free_ipt_policy_member(&ipt_policy);
    return ret;
}

int write_iptables_forward(int fd, policy_t *policy)
{
    if(!policy->enable) {
        return 0;
    }
    int ret;
    psd_t *psd;
    char buff[LEN_CMD] = {0};
    ipt_policy_t ipt_policy = new_ipt_policy(policy);
    for(psd = ipt_policy.psd_tabs; psd->psdstr != NULL; psd++){
        memset(buff, 0, sizeof(buff));
        sprintf(buff, "iptables -t filter -A %s_forward %s%s%s%s -j %s\n", 
                policy->zone_src, 
                psd->psdstr,
                psd->withport&&ipt_policy.sports?ipt_policy.sports:"",
                psd->withport&&ipt_policy.dports?ipt_policy.dports:"",
                ipt_policy.extra?:"",
                ipt_policy.target?:"DROP");
        ret = my_write(fd, buff, strlen(buff));
    }
    free_ipt_policy_member(&ipt_policy);
    return ret;
}

int write_iptables_dnat(int fd, policy_t *policy)
{
    if(!policy->enable) {
        return 0;
    }
    int ret;
    psd_t *psd;
    char buff[LEN_CMD] = {0};
    ipt_policy_t ipt_policy = new_ipt_policy(policy);
    for(psd = ipt_policy.psd_tabs; psd->psdstr != NULL; psd++){
        memset(buff, 0, sizeof(buff));
        sprintf(buff, "iptables -t nat -A %s_prerouting %s%s%s%s -j %s\n", 
                policy->zone_src, 
                psd->psdstr,
                psd->withport&&ipt_policy.sports?ipt_policy.sports:"",
                psd->withport&&ipt_policy.dports?ipt_policy.dports:"",
                ipt_policy.extra?:"",
                ipt_policy.target?:"ACCEPT");
        ret = my_write(fd, buff, strlen(buff));
    }
    free_ipt_policy_member(&ipt_policy);
    return ret;
}


int write_iptables_snat(int fd, policy_t *policy)
{
    if(!policy->enable) {
        return 0;
    }
    int ret;
    psd_t *psd;
    char buff[LEN_CMD] = {0};
    ipt_policy_t ipt_policy = new_ipt_policy(policy);
    for(psd = ipt_policy.psd_tabs; psd->psdstr != NULL; psd++){
        memset(buff, 0, sizeof(buff));
        sprintf(buff, "iptables -t nat -A %s_postrouting %s%s%s%s -j %s\n", 
                policy->zone_src, 
                psd->psdstr,
                psd->withport&&ipt_policy.sports?ipt_policy.sports:"",
                psd->withport&&ipt_policy.dports?ipt_policy.dports:"",
                ipt_policy.extra?:"",
                ipt_policy.target?:"ACCEPT");
        ret = my_write(fd, buff, strlen(buff));
    }
    free_ipt_policy_member(&ipt_policy);
    return ret;
}



int iptables_run_script(const char *script)
{
    sighandler_t old_handler = signal(SIGCHLD, SIG_DFL);
    int ret = system(script);
    signal(SIGCHLD, old_handler);
    return ret;
}


