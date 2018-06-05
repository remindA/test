

/*
 * io复用实现代理服务器
 * 1. 同时维持两个连接
 * 2. 作为服务器响应客户端
 * 3. 作为客户端请求服务器资源
 */


/*
 * 服务器与客户端之间共享数据内容
 */
typedef struct {
    void *data;
    size_t len;
}my_data_t;

struct {
    int client;
    int server;
    my_data_t data_c2s;
    my_data_t data_s2c;
}

while(true) {
    read_parse_http_header();
    read_parse_http_body();

}

/* fsm header */
HEADER_BRK
HEADER_CON
HEADER_BAD
HEADER_ERR
HEADER_AGN

LINE_OK
LINE_NEED
LINE_AGN

REQ_LINE_OK
REQ_LINE_BAD
REQ_LINE_ERR

FIELD_OK
FIELD_BAD
FIELD_ERR


while(1) {
switch(header->state) {
    case HEADER_BRK:
        break;
    case HEADER_CON:
        http_read_header(header);
        http_parse_header(header);
        break;
    case HEADER_BAD:
    case HEADER_ERR:
}
}







