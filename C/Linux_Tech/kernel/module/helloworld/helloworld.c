/*
 * =====================================================================================
 *
 *       Filename:  helloworld.c
 *
 *    Description:  第一个linux module编写
 *
 *        Version:  1.0
 *        Created:  2018年08月28日 17时05分35秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  NYB (), niuyabeng@126.com
 *   Organization:  
 *
 * =====================================================================================
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NYB");


int helloworld_init(void)
{
    printk("===== helloworld_init: start =====\n");
    printk("Hello World!\n");
    printk("===== helloworld_init: end =====\n");
    return 0; 
}

void helloworld_exit(void)
{
    printk("===== helloworld_exit: start =====\n");
    printk("===== helloworld_exit: end =====\n");
}
 
module_init(helloworld_init);
module_exit(helloworld_exit);

