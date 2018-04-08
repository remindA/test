#include "zone.h"
#include "pool.h"
#include "policy.h"
#include "iptables.h"

struct list_head *zone;
struct list_head *pool;
struct list_head *policy;
struct list_head *ipt_init;
struct list_head *ipt_zone;
struct list_head *ipt_policy;

/*
 * 在使用system函数时，注意很可能会发生错误，导致命名致命不完全
 */

int main()
{
    char *cfg_zone   = NULL;
    char *cfg_pool   = NULL;
    char *cfg_policy = NULL;
    cfg_zone = cfg_pool = cfg_policy = "firewall";
    zone = parse_zone_list(cfg_zone);
    pool = parse_pool_list(cfg_pool);
    policy = parse_policy_list(cfg_policy);
    if(NULL == zone || NULL == pool || NULL == policy) {
        printf("cannot parse zone-'%s' or pool-'%s' or policy-'%s'\n", cfg_zone, cfg_pool, cfg_policy);
    }
    make_fw_run_script("/var/run/hxha_fw_run.sh", zone, policy);
    make_fw_flush_script("/var/run/hxha_fw_flush.sh", zone);
    iptables_run_script("sh /var/run/hxha_fw_run.sh");
     
    //check_zone_policy(zone, policy);
    //ipt_init_print();
    //ipt_zone_print(zone);
    //ipt_policy_print(policy, POLICY_ALL);

    return 0;
}


