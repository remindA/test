#ifndef _SAA_INCLUDE_H_
#define _SAA_INCLUDE_H_
/* 服务器和客户端约定 */
#define DEBUG                   1

#define LEN_ERR                 (-2)
#define LEN_MCHN_CODE           128
#define LEN_ADDR_LIST           (16 * 16)   //暂定最多16个ip地址
#define LEN_ACCESS_TIME         128

#define LEN_IP                  4
#define LEN_IP_STR              16
#define LEN_MAC                 6
#define LEN_MAC_STR             18


/*

   协议：
   =================================
   | 头 | FLAG | 数据（可选） | 尾 |
   =================================
*/

/* 类型定义（随意扩展） */
#define SAA_TYPE_HEAD            0x5555           //头
#define SAA_TYPE_TAIL            0x5444           //尾
#define VERSION_1                0x4010           //版本
#define VERSION_2                0x4020           //版本
#define VERSION_3                0x4030           //版本
#define RESERVE                  0x00
/*
=======================================================
|           服务器收       |           服务器回复     |
|-----------------------------------------------------|
|   SAA_FLAG_REQUEST       |   SAA_FLAG_REPLY         |
|-----------------------------------------------------|
|   SAA_FLAG_HEARTBEAT     |   SAA_FLAG_HEARTBEAT     |
|-----------------------------------------------------|
|   SAA_FLAG_ADDR_LIST     |   SAA_FLAG_ADDR_LIST     |
|-----------------------------------------------------|
|   SAA_FLAG_AUTH_STATE    |   SAA_FLAG_AUTH_STATE    |
=======================================================
*/

#define SAA_FLAG_REQUEST     0x1000          //客户端请求认证：包含客户端的信息"客户端可选择手动发送，或者自动定时发送，一般软件运行后发送一次即可"

#define SAA_FLAG_REPLY       0x1001          //回复认证状态：数据为认证状态
#define SAA_FLAG_HEARTBEAT   0x1002          //心跳：不含数据
//#define SAA_FLAG_ADDR_LIST   0x1003          //（客户端询问/服务器回复）访问地址列表
#define SAA_FLAG_AUTH_STATE  0x1004          //（客户端询问/服务器回复）认证状态（这个可以当做心跳来使用）
//#define SAA_FLAG_ACCESS_TIME 0x1005          //访问时间段


#define SAA_TYPE_IP          0x20
#define SAA_TYPE_MAC         0x21
#define SAA_TYPE_AUTH_STATE  0X22

#define VALUE_AUTH_STATE_YES      "1"
#define VALUE_AUTH_STATE_NO       "0"

#define VALUE_NONE                ""
#define VALUE_PAD                 " "
//#define SAA_ADDR_LIST_DEFAULT     "0.0.0.0"
//#define SAA_ACCESS_TIME_DEFAULT   "00:00-24:00"

#define HEARTBEAT_INTERVAL        5
#define TIMEOUT_READ 	          (2 * HEARTBEAT_INTERVAL)

typedef struct
{					
    char ip[LEN_IP_STR];
    char mac[LEN_MAC_STR];
}s_client_info;


#pragma pack(1)
typedef struct
{
    unsigned short head;
    unsigned short ver;
    unsigned char  rsrv;
    unsigned short flag;
    unsigned short len;
}packet_head_t;

/* end of 服务器和客户端约定 */


/* 服务器专区 */
#define PATH_AUTH					"include/auth_file"         //认证表文件的存放路径
#define LINE_LEN					(sizeof(saa_element) + 10)  //认证表文件一行的最大长度

/* 此结构体中的数据全部填充至认证表行
 * 可扩充：后期可能会添加允许访问地址列表
 */
typedef struct
{
    s_client_info client_info;          //客户端发来的请求信息
    char auth_state[2];                 //认证状态。1：已认证 O：待认证
    //char addr_list[LEN_ADDR_LIST];       //允许访问的地址列表（08.04保留尚未启用）
    //char access_time[]
}saa_element;

typedef saa_element s_element;

typedef struct saa_node
{
    s_element element;
    struct saa_node *next;
}s_list_node;

/* end of 服务器专区 */



/* 客户端专区 */
/* end of 客户端专区 */


#endif
