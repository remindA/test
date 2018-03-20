/*
 * =====================================================================================
 *
 *       Filename:  policy.h
 *
 *    Description:  安全策略头文件定义
 *
 *        Version:  1.0
 *        Created:  2018年03月20日 12时17分17秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  NYB 
 *   Organization:  
 *
 * =====================================================================================
 */
enum spolicy_type{
    POLICY_LOCAL   = 0,
    POLICY_FORWARD = 1,
};



typedef struct{
    const char *name;
    enum spolicy_type  type;    // *
    struct zone *zone_src;      // *
    struct zone *zone_dst;
    int p;
    const char *s;
    const char *d;
    const char *sports;
    const char *dports;
    const char *time;
    const char *target;
    const char *extra;
}spolicy_t;
