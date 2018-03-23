#include "zone.h"
#include "policy.h"

struct list_head *zone;
struct list_head *policy;

struct ipt_cmd{
    char *cmd;
    struct list_head list;
}


/*
 * 在使用system函数时，注意很可能会发生错误，导致命名致命不完全
 */

int main()
{
    zone = get_zone_list("zone");
    policy = get_policy_list("policy");
}

typedef struct{
    char string[64];
}string_t;

const string_t chains_dispatch[] = {
    {"pre"},
    {"post"},
    {"input"},
    {"output"},
    {"forward"},
    {NULL}
}


void ipt_default_policy()
{
    system("iptables -t filter -P INPUT DROP");
    system("iptables -t filter -P OUTPUT DROP");
    system("iptables -t filter -P FORWARD DROP");
}

void ipt_flush()
{
    system("iptables -t filter -F INPUT");
    system("iptables -t filter -F OUTPUT");
    system("iptables -t filter -F FORWARD");
    system("iptables -t nat    -F PREROUTING");
    system("iptables -t nat    -F POSTROUTING");
}

void ipt_create_dispatch()
{
    system("iptables -t filter -N dispatch_input");
    system("iptables -t filter -N dispatch_output");
    system("iptables -t filter -N dispatch_forward");
    system("iptables -t nat    -N dispatch_prerouting");
    system("iptables -t nat    -N dispatch_postrouting");
}

struct list_head *ipt_zone(struct list_head *head)
{
    struct list_head *pos;
    list_for_each(pos, head){
        zone_t *zone = list_entry(pos, zone_t, list);
        /* create chains */
        system("iptables -t nat    -N %s_prerouting",  zone->name);
        system("iptables -t nat    -N %s_postrouting", zone->name);
        system("iptables -t filter -N %s_input",       zone->name);
        system("iptables -t filter -N %s_output",      zone->name);
        system("iptables -t filter -N %s_forward",     zone->name);

        /* refer new chains */
        system("iptables -t nat -A PREROUTING  -i %s -j %s_prerouting",  zone->iface, zone_name);
        system("iptables -t nat -A POSTROUTING -o %s -j %s_postrouting", zone->iface, zone_name);
        system("iptables -t filter -A INPUT    -i %s -j %s_input",       zone->iface, zone_name);
        system("iptables -t filter -A OUTPUT   -o %s -j %s_output",      zone->iface, zone_name);
        system("iptables -t filter -A FORWARD  -i %s -j %s_forward",     zone->iface, zone_name);

    }
}

struct ipt_local_policy(struct list_head *head)
{
    struct list_head *pos;
    list_for_each(pos, head){
        policy_t *policy = list_entry(pos, policy_t, list);
        if(strcmp(policy->type, "local") == 0){
            system("iptables -t filter -A %s_input"
        }
        else if(strcmp(policy->type, "forward") == 0){

        }
    }
}
