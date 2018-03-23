#ifndef _INCLUDE_H
#define _INCLUDE_H
#include "list.h"
#include "safe_free.h"

#define LEN_NET_NAME    64
#define LEN_PROTO_NAME  32
#define LEN_ZONE_NAME   32
/*最长: 2018-12-12 12:12:12*/
#define LEN_DATE     24
/*最长: 12:12:12*/
#define LEN_TIME     10
/* 最长: 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31 */
#define LEN_MONTH    85

#define LEN_IP       16
#define LEN_CMD      512
#define BLANK_SPACE  ' '     
#define IP_ALL       "0.0.0.0/0"



/******************************
 *     为zone定义的结构体
 *****************************/
typedef struct {
    char name[LEN_ZONE_NAME];
    char network[LEN_NET_NAME];
    char iface[LEN_NET_NAME];
    struct list_head list;
}zone_t;







/******************************
 *     为policy定义的结构体
 *****************************/

enum policy_type {
    POLICY_LOCAL   = 0,
    POLICY_FORWARD = 1,
    POLICY_DNAT    = 2,
    POLICY_SNAT    = 3,
};
enum ipt_chain{
    CHAIN_PREROUTING  = 0,
    CHAIN_POSTROUTING = 1,
    CHAIN_INPUT       = 2,
    CHAIN_OUTPUT      = 3,
    CHAIN_FORWARD     = 4,
};


typedef struct {
    int   withport;
    char *psdstr;
}psd_t;

/*
 * 一个policy可能需要生成好几条iptables命令
 */
typedef struct {
    enum policy_type type;
    psd_t *psd_tabs;
    char  *sports;
    char  *dports;
    char  *time;
    char  *extra;
    char  *target;
}ipt_policy_t;



enum ipt_target {
    TARGET_ACCEPT = 0,
    TARGET_DROP   = 1,
    TARGET_REJECT = 2,
};

/*
 * 协议
 * -p tcp　一次只能一个协议，只有tcp和udp有端口
 * ipt_proto_t proto[] = {
 *      {"tcp"},
 *      {"udp"},
 *      {"icmp"},
 *      {NULL}
 * }
 */
typedef struct{
    struct list_head list;
    int  reverse;
    char pname[LEN_PROTO_NAME];
}ipt_proto_t;


/*
 * 源地址和目的地址
 * -s/-d 192.168.1.1
 * -s/-d 192.168.1.2,192.168.1.0/24
 * ! -s 192.168.1.1
 * ! -s 192.168.1.0/24
 * -m iprange --src-range/--dst-range 192.168.1.5-192.168.1.10
 * -m iprange ! --src-range/--dst-range 192.168.1.5-192.168.1.10
 */
typedef struct{
    int iprange;
    int reverse;
    /* -s和 --src-range连用，--src-ragne会失效
     * -s 192.168.2.111 -m iprange --src-range 192.168.110-120
     */
    char *ip;
    struct list_head list;
}ipt_ipaddr_t;


/*
 * 端口
 * --sport/--dport 80:
 * --sport/--dport 80
 * --sport/--dport 80:8080
 * -m multiport --sports/dports 80,8080
 * -m multiport --sports/dports 21,80:8080
 * mutiport也支持portrange，但是格式不允许　":80"和"8080:"(网页上限制，不允许这种格式)
 */

/*
 * 时间
    --datestart time     Start and stop time, to be given in ISO 8601
    --datestop time      (YYYY[-MM[-DD[Thh[:mm[:ss]]]]])
    --timestart time     Start and stop daytime (hh:mm[:ss])
    --timestop time      (between 00:00:00 and 23:59:59)
[!] --monthdays value    List of days on which to match, separated by comma
                         (Possible days: 1 to 31; defaults to all)
[!] --weekdays value     List of weekdays on which to match, sep. by comma
                         (Possible days: Mon,Tue,Wed,Thu,Fri,Sat,Sun or 1 to 7
                         Defaults to all weekdays.)
    --localtz/--utc      Time is interpreted as UTC/local time
*/
typedef struct{
    char *datestart;
    char *datestop;
    char *timestart;
    char *timestop;
    char *monthdays;
    char *weekdays;
    char *timezone;
}ipt_time_t;

typedef struct{
    struct list_head list;
    enum     policy_type type;  //
    char     name[LEN_ZONE_NAME]; //policy
    char     zone_src[LEN_ZONE_NAME];          // nat需要用到zone的接口ip
    char     zone_dst[LEN_ZONE_NAME];          //
    struct list_head proto;     //
    struct list_head src;          //
    struct list_head dst;          //
    char    *sports;            //没有","就用　--sport
    char    *dports;            //有就用 -m mutiport --sports
    ipt_time_t *time;            //
    enum     ipt_target target; //
    char    *extra;
    /*
    char *nat_ip；
    char *nat_port;
     */
}policy_t;

#endif
