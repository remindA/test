/*
 * =====================================================================================
 *
 *       Filename:  main.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年09月06日 10时44分31秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  NYB (), niuyabeng@126.com
 *   Organization:  
 *
 * =====================================================================================
 */

#include "ezxml.h"
#include <stdio.h>

int main(int argc, char **argv)
{
    if(argc != 2) {
        printf("Usage: %s xxx.xml\n", argv[0]);
        return 0;
    }
    ezxml_t ehome = ezxml_parse_file(argv[1]);
    if(NULL == ehome) {
        printf("Cannot ezxml_parse_file %s\n", argv[1]);
        return 0;
    }
    ezxml_t CommandType = ezxml_child(ehome, "CommandType");
    ezxml_t Command = ezxml_child(ehome, "Command");
    ezxml_t Params = ezxml_child(ehome, "Params");
    ezxml_t DeviceID = NULL;
    ezxml_t LocalIP = NULL;
    ezxml_t LocalPort = NULL; 
    if(Params && ezxml_name(Params)) {
        DeviceID = ezxml_child(Params, "DeviceID");
        LocalIP = ezxml_child(Params, "LocalIP");
        LocalPort = ezxml_child(Params, "LocalPort");
    }
    if(CommandType && ezxml_name(CommandType)) {
        printf("%s: %s\n", ezxml_name(CommandType), ezxml_txt(CommandType));
    }

    if(Command && ezxml_name(Command)) {
        printf("%s: %s\n", ezxml_name(Command), ezxml_txt(Command));
    }
    
    if(DeviceID && ezxml_name(DeviceID)) {
        printf("%s: %s\n", ezxml_name(DeviceID), ezxml_txt(DeviceID));
    }

    if(LocalIP && ezxml_name(LocalIP)) {
        printf("%s: %s\n", ezxml_name(LocalIP), ezxml_txt(LocalIP));
    }

    if(LocalPort && ezxml_name(LocalPort)) {
        printf("%s: %s\n", ezxml_name(LocalPort), ezxml_txt(LocalPort));
    }

    ezxml_free(ehome);
     
    return 0;
}
