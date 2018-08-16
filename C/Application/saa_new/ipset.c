/*
 * =====================================================================================
 *
 *       Filename:  ipset.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年07月27日 17时31分05秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#include "ipset.h"
#include <stdarg.h>

static int SYSTEM(const char *format, ...)
{
    static char buf[4096]="";
    va_list arg;

    va_start(arg, format);
    vsnprintf(buf,4096, format, arg);
    va_end(arg);
    system(buf);
    usleep(1);
    return 0;
}

void saa_rules_init(void)
{

}

void saa_rules_add(const char *ip, const char *mac)
{

	SYSTEM("ipset --add saa %s", ip);
}

void saa_rules_del(const char *ip, const char *mac)
{
	SYSTEM("ipset --del saa %s", ip);
}

void saa_rules_flush()
{
    SYSTEM("ipset flush saa");
}
