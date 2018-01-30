/*
 * =====================================================================================
 *
 *       Filename:  semun.h
 *
 *    Description:  union senum
 *
 *        Version:  1.0
 *        Created:  2018年01月12日 13时11分30秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#ifndef _SEM_UN_H
#define _SEM_UN_H

union semun {
    int              val;
    struct semid_ds *buf;
    unsigned short  *arry;
#if defined(__linux__)
    struct seminfo  *__buff;
#endif
};

#endif

