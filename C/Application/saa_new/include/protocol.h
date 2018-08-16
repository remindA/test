/*
 * =====================================================================================
 *
 *       Filename:  protocol.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年07月27日 17时33分49秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#ifndef _SAA_PROTOCOL_H_
#define _SAA_PROTOCOL_H_

#pragma pack(1)
typedef struct {
    unsigned short head;
    unsigned short version;
    unsigned char reserve;
    unsigned short cmd;
    unsigned short dlen;
}saa_hdr_t;

typedef struct {
    saa_hdr_t hdr;
    unsigned char *data;
    unsigned short tail;
}saa_pkt_t;

#define ERR_BAD_PKT  -1
#define ERR_NO_MEM   -2

#define VALUE_HEAD     0x5555
#define VALUE_VERSION1 0x4010
#define VALUE_RESERVE  0x00
#define VALUE_TAIL     0x5444

#define CMD_REQ_AUTH             0x1000
#define CMD_RSP_UNAUTH           0x1001
#define CMD_RSP_AUTHED           0x1002
#define CMD_REQ_ACCESS           0x1010
#define CMD_RSP_ACCESS_SUCCESS   0x1011
#define CMD_RSP_ACCESS_FAILURE   0x1012
#define CMD_REQ_EXIST            0x1013
#define CMD_RSP_EXIST            0x1014

#define LEN_IP         4
#define LEN_MAC        6
#define LEN_MACH_CODE  16
#define LEN_AUTH_CODE  16
#define LEN_AUTH_REQ   (LEN_MAC+LEN_MACH_CODE)
#define LEN_ACCESS_REQ (LEN_MAC+LEN_MACH_CODE+LEN_AUTH_CODE)
#define LEN_EXIT_REQ   (LEN_ACCESS_REQ)
#define LEN_AUTHED_RSP (LEN_MACH_CODE+LEN_AUTH_CODE)
#define LEN_MARK       64
#define LEN_IP_STR     17
#define LEN_MAC_STR    18

#define MAX_CLIENT_NUM 100
#define ACCESS_TIMEOUT 5
#define AUTH_TIMEOUT   5
#define ACCESS_ON  1
#define ACCESS_OFF 0

#endif

