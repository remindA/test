/*
 * =====================================================================================
 *
 *       Filename:  server.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年06月05日 20时35分08秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#ifndef _SERVER_H_
#define _SERVER_H_
#include "http.h"

typedef struct {
    void *buff;
    size_t len;
}buffer_t;

typedef struct {
    int conn;
    int state;            /* obj当前的状态 */
    int line_st;
    size_t tot;
    size_t off;         /* buffer.data已解析的偏移量 */
    buffer_t buff_hdr;      /* 缓存 */
    buffer_t buff_bdy;
    http_header_t header; /* header结构体 */
}http_obj_t;


/*
 * 接收
 * 解析
 * 再接收
 * 再解析
 * 处理
 * 结束
 * //发送
 * //已发送
 */
enum {
    _STATE_HEADER_RECV = 0,
    _STATE_HEADER_PARSE,
    _STATE_HEADER_PRCSS,
    _STATE_HEADER_BAD,
    _STATE_HEADER_ERR,
    _STATE_HEADER_END
};

enum {
    _STATE_LINE_FULL = 0,
    _STATE_LINE_HALF
};


enum {
    _STATE_REQLINE_OK = 0,
    _STATE_REQLINE_BAD,
    _STATE_FIELD_OK,
    _STATE_FIELD_BAD
};

#endif

