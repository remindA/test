/*
 * =====================================================================================
 *
 *       Filename:  http_proxy.c
 *
 *    Description:  
 *
 *        Version:  1.3
 *        Created:  2018年01月21日 15时00分13秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  NYB 
 *   Organization:  Hengsion
 *
 * =====================================================================================
 */


#define PCRE2_CODE_UNIT_WIDTH 8
#include <time.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef OpenWRT
#include <zlib.h>
#include <assert.h>
#include <hregister.h>
#endif

#include "err_quit.h"
#include "http.h"
#include "list.h"
#include "pad_rplstr.h"
#include "safe_free.h"
#include "include.h"
#include "str_replace.h"
#include "config.h"

extern int h_errno;    /* for get hostbyname #include <netdb.h> */
extern int proxy;      /* define in http.c */

/* system may failed somtimes, wo need to change signal behavior of SIG_CHLD */
typedef void(*sighandler_t)(int);

/* openssl */
SSL_CTX *ctx_s;
SSL_CTX *ctx_c;
//char *ca_cert_file = "/etc/https_proxy/ca.crt";
char *server_cert_file = "/etc/http_proxy/server.crt";
char *private_key_file = "/etc/http_proxy/server.key";


/* 其他 */
int l_fd;
pcre2_code *ge_re;
struct list_head *remap_table;
struct list_head *regex_table;

map_t *map_tab;
char lan_ip[24] = {0};
char wan_ip[24] = {0};

/*
 * after init_remap_tab
 * it is like
 * remap_tab = {
 *  {"lan_if_ip", {"lan_ip1", "lan_ip2", "lan_ip3"}},
 *  {"wan_if_ip", {"wan_ip1", "wan_ip2", "wan_ip3"}},
 * }
 * */

void usage(const char *name);
void sig_handler(int signo);
int ssl_init(void);
int proxy_listen(void);
void worker_thread(void *ARG);
int read_process_forward(int fd_from,  SSL *ssl_from, int *fd_to, SSL **ssl_to, pcre2_code **regex);
int read_all_txt_chunk_m(int fd, SSL *ssl, unsigned char **all_chunk, unsigned int *len);
int read_forward_txt_chunk(int fd_from, SSL *ssl_from, int fd_to, SSL *ssl_to, int encd, int direction, pcre2_code *re);
int forward_txt_none(int fd, SSL *ssl, http_header_t *header, unsigned char *body, int len, int whole, int encd, int direction, pcre2_code *re);
int read_forward_none_txt(int fd_from, SSL *ssl_from, int fd_to, SSL *ssl_to, int len_body);
int create_proxy_server(char *host, short l_port, int listen_num);
int create_real_server(const char *host, short port);
int create_real_server_nonblock(const char *host, short port, int sec);
PCRE2_SPTR replace_content_default_m(char *old, int direction, pcre2_code *re);
int rewrite_url(char *url, int max, pcre2_code *re, int direction);
int replace_field(char *field_value, int direction, pcre2_code *re);
int replace_http_header(http_header_t *header, pcre2_code *re, int direction);
int get_gunzip(unsigned char *src, unsigned int len_s, char **dst, unsigned int *len_d);
#if 0
#ifdef OpenWRT
int http_gunzip(unsigned char *source, unsigned int s_len, unsigned char **dest, unsigned int *d_len, int gzip);
#endif
#endif
int SYSTEM(const char *format, ...);
int find_ifaceip_by_realip(const char *realip, char *ifaceip);
int find_remapip_by_realip(const char *realip, char *remapip);
void do_redirect(char *file);

int SYSTEM(const char *format, ...)
{
#if 0
	FILE *pf,*pft;
#endif
	static char buf[4096]="";
	va_list arg;

	memset(buf, 0, sizeof(buf));

	va_start(arg, format);
	vsnprintf(buf,4096, format, arg);
	va_end(arg);
	syslog(LOG_INFO, "%s\n",buf);   

    sighandler_t old_handler = signal(SIGCHLD, SIG_DFL);
    system(buf);
    signal(SIGCHLD, old_handler);

	usleep(1000);
	return 0;
}

int find_ifaceip_by_realip(const char *realip, char *ifaceip)
{
    //char lanip[24];
	//char wanip[24];
	//hsion_get_ip(LAN_INTERFACE, lanip, sizeof(lanip));
	//hsion_get_ip(WAN_INTERFACE, wanip, sizeof(wanip));
    struct list_head *pos;
    list_for_each(pos, remap_table) {
        remap_entry_t *entry = list_entry(pos, remap_entry_t, list);
        printf("realip=%s, entry->direction= %d, entry->before=%s\n", realip, entry->direction, entry->before);
        if(strcmp(entry->before, realip) == 0) {
            if(entry->direction == 0) {
                //lan2wan
                strcpy(ifaceip, wan_ip);
            }
            else if(entry->direction == 1) {
                //wan2lan
                strcpy(ifaceip, lan_ip);
            }
            return 1;
        }
    }
    return 0;
}


int find_remapip_by_realip(const char *realip, char *remapip)
{
    struct list_head *pos;
    list_for_each(pos, remap_table) {
        remap_entry_t *entry = list_entry(pos, remap_entry_t, list);
        if(strcmp(entry->before, realip) == 0) {
            strcpy(remapip, entry->after);
            return 1;
        }
    }
    return 0;
}

void do_redirect(char *file)
{
    static struct uci_context *ctx;
    struct uci_package *pkg;
    struct uci_element *e = NULL;

    ctx = uci_alloc_context();
    if(UCI_OK != uci_load(ctx, file, &pkg))
    {
        printf("uci_load(%s) not ok\n", file);
        goto cleanup;
    }

    uci_foreach_element(&pkg->sections, e)
    {
        struct uci_section *s = uci_to_section(e);
        char *type    = uci_lookup_option_string(ctx, s, "type");
        char *ip    = uci_lookup_option_string(ctx, s, "ip");
        char *port  = uci_lookup_option_string(ctx, s, "port");
        char *regex = uci_lookup_option_string(ctx, s, "regex");

        if(!type || !ip || !port) {
            continue;
        }
        //printf("%s,%s,%s\n", type, ip, port);
        char iface_ip[24] = {0};
        char remap_ip[24] = {0};
        find_ifaceip_by_realip(ip, iface_ip);
        find_remapip_by_realip(ip, remap_ip);
        if(strcmp(type, "http") == 0 &&  proxy == HTTP) {
            SYSTEM("iptables -t nat -I PREROUTING -p tcp -d %s --dport %s -j DNAT --to-destination %s:%d"
            ,remap_ip, port, iface_ip, HTTP_PROXY_PORT);
        }
        else if(strcmp(type, "https") == 0 && proxy == HTTPS) {
            SYSTEM("iptables -t nat -I PREROUTING -p tcp -d %s --dport %s -j DNAT --to-destination %s:%d"
            ,remap_ip, port, iface_ip, HTTP_PROXY_PORT);
        }
    }
cleanup:
    uci_unload(ctx, pkg);
    uci_free_context(ctx);
    ctx = NULL;
}

/* 初始化map_tab
 * @head: remap_table
 */
int init_map_tab(struct list_head *head)
{
    if(head == NULL) {
        return -1;
    }
    map_tab = (map_t *)calloc(__MAP_TAB_MAX, sizeof(map_t));
    if(NULL == map_tab) {
        perror("calloc in init_map_tab");
        return -1;
    }
    int i;
    int cnt = list_count(head);
    for(i = 0; i < __MAP_TAB_MAX; i++) {
        map_tab[i].ip_tab = (ip_t *)calloc(cnt+1, sizeof(ip_t));
        if(NULL == map_tab[i].ip_tab) {
            safe_free(map_tab);
            return -1;
        }
    }

    /* init interface */
    hsion_get_ip(LAN_INTERFACE, lan_ip, sizeof(lan_ip));
    hsion_get_ip(WAN_INTERFACE, wan_ip, sizeof(wan_ip));
    printf("lan_ip: %s\n", lan_ip);
    printf("wan_ip: %s\n", wan_ip);
    map_tab[_LAN].iface = _LAN;
    map_tab[_WAN].iface = _WAN;

    /* init ip tables */
    /* if remap_tables is empty
     * {
     *      {"lan_if_ip", {NULL}},
     *      {"wan_if_ip", {NULL}},
     * }
     */ 
    struct list_head *pos;
    ip_t *plan = map_tab[_LAN].ip_tab;
    ip_t *pwan = map_tab[_WAN].ip_tab;
    list_for_each(pos, head) {
        remap_entry_t *entry = list_entry(pos, remap_entry_t, list);
        /*lan2wan*/
        if(entry->direction == 0) {
            plan->ip = entry->before;
            pwan->ip = entry->after;
            printf("%s %s\n", plan->ip, pwan->ip);
            plan++;
            pwan++;
        }
        /*wan2lan*/
        else if(entry->direction == 1) {
            plan->ip = entry->after;
            pwan->ip = entry->before;
            printf("%s %s\n", plan->ip, pwan->ip);
            plan++;
            pwan++;
        }
    }
    return 0;
}

int from_lan_or_wan(int fd)
{
    struct sockaddr_in sock;
    socklen_t len = sizeof(sock);
    getsockname(fd, (struct sockaddr *)&sock, &len);
    //printf("from_lan_or_wan: lan_ip:[%s], wan_ip:[%s], from_ip:[%s]\n", lan_ip, wan_ip, inet_ntoa(sock.sin_addr));
    if(strcmp(lan_ip, inet_ntoa(sock.sin_addr)) == 0) {
        //printf("from_ip, is lan2wan\n");
        return LAN2WAN;
	}
    else if(strcmp(wan_ip, inet_ntoa(sock.sin_addr)) == 0) {
       // printf("from_ip is, wan2lan\n");
    	return WAN2LAN;
    }
    else {
        //printf("from_ip is nothing\n");
    	return -1;
	}
}


int main(int argc, char **argv)
{
    //监听的端口，缺省使用默认值
    int opt;
    if(argc != 2) {
        usage(argv[0]);
        return 0;
    }
    while((opt = getopt(argc, argv, "dsv")) != -1) {
        switch(opt) {
            case 's':
                proxy = HTTPS;
                break;
            case 'd':
                proxy = HTTP;
                break;
            case 'v':
                printf("%s_%s\n", argv[0], VERSION);
                return 0;
            default:
                usage(argv[0]);
                return 0;
        }
    }

    openlog("http_proxy", LOG_CONS, LOG_USER);
    /* 开关控制 */
    int http_on = get_http_switch("http_proxy");
    if(!http_on) return 0;

    /* get_remap_table */
    remap_table = get_remap_table_m("remap");
    if(NULL == remap_table) {
        fprintf(stderr, "get_remap_table_m failed, 映射表解析失败\n");
        syslog(LOG_INFO, "%s启动失败-解析映射表(get_remap_table_m)", argv[0]); 
        exit(0);
    }

    /* get_regex_table */
    regex_table = get_regex_table_m("http_proxy");

    /* get general_regex */
    ge_re = get_general_regex("http_proxy");
    if(ge_re == NULL)
    {
        fprintf(stderr, "general_regex is NULL,通用规则是空\n");
        syslog(LOG_INFO, "%s启动失败-必填项:通用规则为空(get_general_regex)", argv[0]); 
        exit(0);
    }
#ifdef DEBUG_CONFIG
    printf("general_regex exists = %p\n", ge_re);
#endif
    if(init_map_tab(remap_table) < 0) {
        fprintf(stderr, "general_regex is NULL\n");
        syslog(LOG_INFO, "%s启动失败-init_map_tab不成功", argv[0]); 
        exit(0);
    }

    sleep(2);
    do_redirect("http_proxy");

    /* 初始化openssl, ctx_s, ctx_c等 */
    if(proxy == HTTPS && ssl_init() < 0) {
        fprintf(stderr, "cannot ssl_init()\n");
        syslog(LOG_INFO, "ssl_init failed");
        return 0;
    }

    /* 建立socket */
    int   l_num = 100;
    char  l_host[] = "0.0.0.0";
    short l_port = (proxy == HTTP)?HTTP_PROXY_PORT:HTTPS_PROXY_PORT;
    l_fd = create_proxy_server(l_host, l_port, l_num);
    if(l_fd < 0) {
        printf("cannot create proxy server\n");
        syslog(LOG_INFO, "create proxy server failed");
        return 0;
    }
    /* 监听 */
    switch(fork()) {
        case 0:
            printf("%s在后台启动\n", argv[0]);
            if(proxy == HTTP) {
                syslog(LOG_INFO, "%s程序启动: http proxy", argv[0]); 
            }
            if(proxy == HTTPS) {
                syslog(LOG_INFO, "%s程序启动: https proxy", argv[0]); 
            }
            proxy_listen();
            exit(0);
        case -1:
            printf("fork()监听进程失败\n");
            syslog(LOG_INFO, "%s启动失败: fork failed", argv[0]); 
            err_quit("fork()");
            break;
        default:
            break;
    }
    return 0;
}

void usage(const char *name)
{
    printf("%s [option]\n", name);
    printf("\t-d \tAs http_proxy, listen on port %d\n", HTTP_PROXY_PORT);
    printf("\t-s \tAs https_proxy, listen on port %d\n", HTTPS_PROXY_PORT);
    printf("\t-v \tVersion\n");
}

/*
 *  worker:
 *          SIGPIPE: 忽略
 *          SIGHUP: 退出进程
 *  
 */
void sig_handler(int signo)
{
    switch(signo) {
        case SIGUSR1:
            if(proxy == HTTP) {
                syslog(LOG_INFO, "http_proxy exit SIGUSR1");
                exit(1);
            }
            break;
        case SIGUSR2:
            if(proxy == HTTPS){
                syslog(LOG_INFO, "https_proxys exit SIGUSR2");
                exit(1);
            }
            break;
        case SIGPIPE:
            if(proxy == HTTP) {
                syslog(LOG_INFO, "http_proxy ignore SIGPIPE", signo);
            }
            if(proxy == HTTPS) {
                syslog(LOG_INFO, "http_proxys ignore SIGPIPE", signo);
            }
            break;
        default:
            if(proxy == HTTP) {
                syslog(LOG_INFO, "http_proxy exit because of sig_%d", signo);
            }
            if(proxy == HTTPS) {
                syslog(LOG_INFO, "http_proxys exit because of sig_%d", signo);
            }
            exit(1);
    }
}


int ssl_init(void)
{ 
#ifdef FUNC
    printf("==========start ssl_init()==========\n");
#endif
    SSL_load_error_strings();
    //OpenSSL_add_ssl_algorithms();
    SSL_library_init();

    ctx_c = SSL_CTX_new(TLSv1_2_client_method());  //代理客户端
    if(!ctx_c) {
#ifdef DEBUG_SSL
        printf("cannot create ctx_c\n");
#endif
        return -1;
    }
    ctx_s = SSL_CTX_new(TLSv1_2_server_method());  //代理服务器
    if(!ctx_s) {
#ifdef DEBUG_SSL
        printf("cannot create ctx_s\n");
#endif
        return -1;
    }

    //SSL_CTX_set_verify(ctx_s, SSL_VERIFY_NONE, NULL);
    //SSL_CTX_set_verify(ctx_s, SSL_VERIFY_PEER, NULL);
    //SSL_CTX_load_verify_locations(ctx_s, ca_cert_file, NULL);
    if(SSL_CTX_use_certificate_file(ctx_s, server_cert_file, SSL_FILETYPE_PEM) <= 0) {
#ifdef DEBUG_SSL
        printf("cannot load server certificate file\n");
#endif
        return -1;
    }
    if(SSL_CTX_use_PrivateKey_file(ctx_s, private_key_file, SSL_FILETYPE_PEM) <= 0) {
#ifdef DEBUG_SSL
        printf("cannot load server private key file\n");
#endif
        return -1;
    }
    if(!SSL_CTX_check_private_key(ctx_s)) {
#ifdef DEBUG_SSL
        printf("cannot match server_cert_file and private_key_file\n");
#endif
        return -1;
    }
    //SSL_CTX_set_cipher_list(ctx_s, "RC4-MD5");
    //SSL_CTX_set_cipher_list(ctx_s, "AES256-GCM-SHA384");
    SSL_CTX_set_cipher_list(ctx_s, "ALL");
    SSL_CTX_set_mode(ctx_s, SSL_MODE_AUTO_RETRY);
#ifdef FUNC
    printf("==========finish ssl_init()==========\n");
#endif
    return 0;
}

int proxy_listen(void)
{
    printf("\n==========start proxy_listen(%d)==========\n", getpid());
    if(signal(SIGINT, sig_handler) == SIG_ERR) {
        err_quit("signal()");
    }
    printf("register SIGINT=%d\n", SIGINT);

    if(signal(SIGSEGV, sig_handler) == SIG_ERR) {
        err_quit("signal()");
    }
    printf("register SIGSEGV=%d\n", SIGSEGV);

    if(signal(SIGPIPE, sig_handler) == SIG_ERR) {
        err_quit("signal()");
    }
    printf("register SIGPIPE=%d\n", SIGPIPE);

    if(signal(SIGUSR1, sig_handler) == SIG_ERR) {
        err_quit("signal()");
    }
    printf("register SIGUSR1=%d\n", SIGUSR1);

    if(signal(SIGUSR2, sig_handler) == SIG_ERR) {
        err_quit("signal()");
    }
    printf("register SIGUSR2=%d\n", SIGUSR2);

    struct sockaddr_in client_addr;
    bzero(&client_addr, sizeof(client_addr));
    socklen_t len_client = sizeof(client_addr);
    int c_fd;
    int cnt = 0;
    while(1) {
        c_fd = accept(l_fd, (struct sockaddr *)&client_addr, &len_client);
        if(c_fd < 0) {
            perror("cannot accept correctly, accept()");
            continue;
        }
        int *fd = (int *)malloc(sizeof(int));
        if(NULL == fd) {
            perror("malloc()");
            continue;
        }
        /*
        struct sockaddr_in sock;
        socklen_t sock_len = sizeof(sock);
        if(0 == getsockname(c_fd, (struct sockaddr *)&sock, &sock_len)) {
            printf("\nClient coming from %s :%d\n", inet_ntoa(sock.sin_addr), ntohs(sock.sin_port));
        }
        else {
            perror("getsockname");
        }
        */
        *fd = c_fd;
        pthread_t th3;
        if(pthread_create(&th3, NULL, (void *)worker_thread, (void *)fd) < 0) {
            perror("pthread_create()");
            close(*fd);
            SAFE_FREE(fd);
        }
    }
    //隐式回收
    printf("==========finish proxy_listen()==========\n");
    return 0;
}

void worker_thread(void *ARG)
{
    /* thread init */
    int ret;
    int tid = getpid();
    pthread_detach(pthread_self());
    int c_fd = *((int *)ARG);
    SAFE_FREE(ARG);

    int s_fd = -1;
    SSL *ssl_s = NULL;
    SSL *ssl_c = NULL;
    pcre2_code *re = NULL;
    if(proxy == HTTPS) {
#ifdef TIME_COST
        struct timeval st;
        struct timeval ed;
        gettimeofday(&st, NULL);
#endif
        /* ssl */
        ssl_s = SSL_new(ctx_s);
        if(NULL == ssl_s) {
            printf("handle_client(%d): cannot create ssl\n", tid);
            goto worker_exit;
        }
        ret = SSL_set_fd(ssl_s, c_fd);
        if(ret != 1) {
            print_ssl_error(ssl_s, ret, "handle_client: SSL_set_fd");
            goto worker_exit;
        }
        if((ret = SSL_accept(ssl_s)) == 0) {
            print_ssl_error(ssl_s, ret, "handle_client: SSL_accept()");
            goto worker_exit;
        }
#ifdef TIME_COST
        gettimeofday(&ed, NULL);
        printf("ssl_accept total use  %ldms\n", (ed.tv_sec-st.tv_sec)*1000 + (ed.tv_usec-st.tv_usec)/1000);
        syslog(LOG_INFO, "ssl_accept total use  %ldms\n", (ed.tv_sec-st.tv_sec)*1000 + (ed.tv_usec-st.tv_usec)/1000);
#endif
    }
    while(1) {
        ret = read_process_forward(c_fd, ssl_s, &s_fd, &ssl_c, &re);
        if(ret < 0) {
            break;
        }
        else if(ret == 0) {
            break;
        }
        ret = read_process_forward(s_fd, ssl_c, &c_fd, &ssl_s, &re);
        if(ret < 0) {
            break;
        }
        else if(ret == 0) {
            break;
        }
    }
worker_exit:
    if(ssl_s != NULL) {
        SSL_shutdown(ssl_s);
        SSL_free(ssl_s);
    }
    if(ssl_c != NULL) {
        SSL_shutdown(ssl_c);
        SSL_free(ssl_c);
    }

    close(c_fd);
    if(s_fd > 0) {
        close(s_fd);
    }
#ifdef DEBUG
    printf("==========worker_thread() exit==========\n");
#endif
    pthread_exit(&ret);
}



/*
 * return: 
 *  <= 0 : failed
 *  > 0  : ok
 *  第一次调用时:(肯定是request)
 *      会在函数内解析header
 *      然后connect到真正服务器的地址，保存fd_to, ssl_to(https), regex
 *      根据服务器地址确定正则表达式
 *  第二次调用就是response
 *
 *  之后的每次调用都是一次request，一次response
 */
int read_process_forward(int fd_from,  SSL *ssl_from, int *fd_to, SSL **ssl_to, pcre2_code **regex)
{
#ifdef RPS
    printf("==========start read_process_forward()==========\n");
#endif
    int  pr;
    int  len;
    int  ret;
    int  encd;
    int  direction;
    int  req_or_rsp;
    short port;
    char *gunzip = NULL;
    char *before_ip = NULL;
    char host[LEN_HOST] = {0};
    char buff_header[LEN_HEADER] = {0};
    unsigned int  len_gunzip = 0;
    PCRE2_SPTR new_body = NULL;
    pcre2_code *re;

    direction = from_lan_or_wan(fd_from);

    /* 1. 读http头 */
    ret = read_http_header(fd_from, ssl_from, buff_header, sizeof(buff_header) - 1);
    if(ret <= 0) {
#ifdef RPS
        printf("cannot read_http_header\n");
#endif
        return ret;
    }

    /* 2. 解析http头 */
    http_header_t *header = (http_header_t *)calloc(1, sizeof(http_header_t));
    init_list_head(&(header->head));

    if(parse_http_header(buff_header, header) < 0) {
#ifdef RPS
        printf("cannot parse_http_header(%s)\n", buff_header);
#endif
        return -1;
    }

    /* 3. 获取host:port和before_ip, 这里的host是映射后的地址 */
    get_host_port(header, host, &port);
    before_ip = get_ip_before_remap(remap_table, host);

    /* 第一次请求包, 创建连接, 确定regex, 获取服务器的session*/
    req_or_rsp = is_http_req_rsp(header);
    if(req_or_rsp == IS_REQUEST && *fd_to < 0) {
        /* 不在列表中依然可以 */
        struct timeval strt;
        struct timeval end;
        if(before_ip == NULL) {
            before_ip = host;
            *regex = NULL;
        }
        else {
            if((*regex = get_re_by_host_port(regex_table, before_ip, port)) == NULL) {
                *regex = ge_re;
            }
        }
        gettimeofday(&strt, NULL);
        *fd_to = create_real_server(before_ip, port);
        if(*fd_to < 0) {
            return -1;
        }

        /* https ssl connection */
        if(proxy == HTTPS) {
            SSL_SESSION *session;
            session = get_ssl_session(remap_table, before_ip);

            *ssl_to = SSL_new(ctx_c);
            if(NULL == *ssl_to) {
                printf("cannot SSL_new\n");
                close(*fd_to);
                return -1;
            }
            if(session) {
                long tnow  = time(NULL);
                long ctime = SSL_SESSION_get_time(session);
                long tout  = SSL_SESSION_get_timeout(session);
                printf("tnow = %ld, ctime = %ld, diff = %ld, timeout = %ld\n", tnow, ctime, tnow - ctime, tout);
                /* 留3秒 */
                /* 根据超时时间判断似乎并不标准, tout==7200,但是在300秒后就会更新, suoyi  */
                if(time(NULL) - ctime > tout - 3) {
                    SSL_SESSION_free(session);
                    session = NULL;
                }
                else {
                    if(SSL_set_session(*ssl_to, session) == 1) {
                        //printf("SSL_set_session %p ok\n", session);
                        SSL_SESSION_free(session);
                        session = NULL;
                    }
                    else {
                        //printf("cannot SSL_set_session\n");
                    }
                }
            }
            ret = SSL_set_fd(*ssl_to, *fd_to);
            if(ret != 1) {
                print_ssl_error(*ssl_to, ret, "SSL_set_fd ssl_c");
                close(*fd_to);
                SSL_free(*ssl_to);
                return -1;
            }
            ret = SSL_connect(*ssl_to);
            if(ret <= 0) {
                print_ssl_error(*ssl_to, ret, "SSL_connect ssl_c");
                close(*fd_to);
                SSL_free(*ssl_to);
                return -1;
            }
            gettimeofday(&end, NULL);
            session = SSL_get_session(*ssl_to);
            set_ssl_session(remap_table, before_ip, session);
            printf("tcp_ssl_connect total use %ldms\n",
                    (end.tv_sec-strt.tv_sec)*1000 + (end.tv_usec-strt.tv_usec)/1000);
        }
    }
    /* 5. 替换http头 */
    re = *regex;
    replace_http_header(header, re, direction);

    /* 6. 解析优先级，编码，长度信息 */
    len = get_pr_encd(&(header->head), &pr, &encd);
#ifdef RPS
    printf("len = %d, pr = %d, encd = %d\n", len, pr, encd);
#endif
    memset(buff_header, 0, sizeof(buff_header));
    /* 7. 根据优先级替换转发 */
    int mywr;
    switch(pr) {
        case PR_TXT_LEN:
            {
#ifdef RPS
                printf("%d case %d:\n", getpid(), PR_TXT_LEN);
#endif
                /* read body */
                if(len <= 0) {
                    /* post header */
                    http_header_tostr(header, buff_header);
                    mywr = my_write(*fd_to, *ssl_to, "ld", strlen(buff_header), buff_header);
                    if(mywr < 0) {
                        free_http_header(&header);
                        return -1;
                    }
                    break;
                }

                unsigned char *buf_body = (unsigned char *)malloc(len + 1);
                if(NULL == buf_body) {
                    err_quit("malloc buf_body");
                }
                memset(buf_body, 0, len + 1);

                int n = readn(fd_from, ssl_from, buf_body, len);
#ifdef RPS
                printf("pr_txt_len: len = %d, read = %d\n", len, n);
#endif

                if(n < 0) {
#ifdef RPS
                    printf("PR_CONTENT_LEN: read err\n");
#endif
                    free_http_header(&header);
                    return -1;
                }
                if(n == 0) {
                    free_http_header(&header);
#ifdef RPS
                    printf("PR_CONTENT_LEN: read 0\n");
#endif
                    return  0;
                }
                /*
                 * 压缩
                 *      解压成功
                 *          替换成功：修改header(Content-length=new_body, Content-encoding)
                 *          替换失败：修改header(Content-length=gunzip  , Content-encoding)
                 *      解压失败
                 *          不修改header
                 * 未压缩
                 *      替换成功：修改header(Content-length)
                 *      替换失败：不修改header
                 */
                if(encd == ENCD_NONE) {
                    /* 网页未压缩 */
                    new_body = replace_content_default_m((char *)buf_body, direction, re);
                    if(NULL == new_body) {
                        http_header_tostr(header, buff_header);
                        mywr = my_write(*fd_to, *ssl_to, "ldld", strlen(buff_header), buff_header, n, buf_body);
                        if(mywr < 0) {
                            free_http_header(&header);
                            return -1;
                        }
                    }
                    else {
                        rewrite_clen_encd(&(header->head), strlen((char *)new_body), ENCD_KEEP);
                        http_header_tostr(header, buff_header);
                        mywr = my_write(*fd_to, *ssl_to, "ldld", strlen(buff_header), buff_header, strlen((char *)new_body), new_body);
                        if(mywr < 0) {
                            free_http_header(&header);
                            return -1;
                        }
                        printf("write: new_header and new_body %d\n", mywr);
                    }
                }

                else {
                    /* 网页压缩,获取解压内容 */
                    ret = -1;
                    ret = get_gunzip(buf_body, n, &gunzip, &len_gunzip);
                    if(ret == 0){
                        /* 解压成功 */
                        new_body = replace_content_default_m((char *) gunzip, direction, re);
                        if(NULL == new_body) {
                            /* 没有替换,发送原来的压缩数据 */
                            http_header_tostr(header, buff_header);
                            mywr = my_write(*fd_to, *ssl_to, "ldld", strlen(buff_header), buff_header, n, buf_body);
                            if(mywr < 0) {
                                free_http_header(&header);
                                return -1;
                            }
                        }
                        else {
                            /* 替换成功，发送解压并替换后的包 */
                            rewrite_clen_encd(&(header->head), strlen((char *)new_body), ENCD2FLATE);
                            http_header_tostr(header, buff_header);
                            mywr = my_write(*fd_to, *ssl_to, "ldld", strlen(buff_header), buff_header, strlen((char *)new_body), new_body);
                            if(mywr < 0) {
                                free_http_header(&header);
                                return -1;
                            }
                        }
                    }
                    else if(ret != 0 && encd == ENCD_GZIP) {
                        /* 解压失败 */
                        http_header_tostr(header, buff_header);
                        mywr = my_write(*fd_to, *ssl_to, "ldld", strlen(buff_header), buff_header, n, buf_body);
                        if(mywr < 0) {
                            free_http_header(&header);
                            return -1;
                        }
                    }
                }
                SAFE_FREE(gunzip);
                SAFE_FREE(new_body);
                SAFE_FREE(buf_body);
                break;
            }
        case PR_TXT_CHUNK:
            {
#ifdef RPS
                printf("%d case %d:\n", getpid(), PR_TXT_CHUNK);
#endif
                /* send header to handle_client */
                /* loop: read, replace and send to handle_server */
                if(encd == ENCD_FLATE)
                {
                    /* 未压缩 */
                    http_header_tostr(header, buff_header);
                    mywr = my_write(*fd_to, *ssl_to, "ld", strlen(buff_header), buff_header);
                    if(mywr < 0) {
                        free_http_header(&header);
                        return -1;
                    }
                    ret = read_forward_txt_chunk(fd_from, ssl_from, *fd_to, *ssl_to, encd, direction, re);
                    if(ret <= 0) {
                        free_http_header(&header);
                        return ret;
                    }
                }
                else if(encd == ENCD_GZIP)
                {
                    /* 压缩 */
                    int    m = -1;
                    char   chunk_size[64] = {0};
                    unsigned int len_chunk  = 0;
                    unsigned char *all_chunk = NULL;
                    m = read_all_txt_chunk_m(fd_from, ssl_from, &all_chunk, &len_chunk);
                    if(m != 0)
                    {
#ifdef RPS
                        printf("read_all_txt_chunk failed\n");
#endif
                        return -1;
                    }
                    ret = -1;
                    ret = get_gunzip(all_chunk, len_chunk, &gunzip, &len_gunzip);
                    if(ret == 0)
                    {
                        /* 解压成功 */
                        rewrite_encd(&(header->head), ENCD2FLATE);
                        new_body = replace_content_default_m(gunzip, direction, re);
                        if(new_body != NULL)
                        {
                            /* 替换成功 */
                            sprintf(chunk_size, "%x\r\n", strlen((char *)new_body));
                            http_header_tostr(header, buff_header);
                            mywr =  my_write(*fd_to, *ssl_to, "ldldldld",
                                    strlen(buff_header), buff_header,
                                    strlen(chunk_size), chunk_size,
                                    strlen((char *)new_body), new_body,
                                    7, "\r\n0\r\n\r\n");
                            SAFE_FREE(new_body);
                        }
                        else
                        {
                            /* 未替换 */
                            sprintf(chunk_size, "%x\r\n", len_gunzip);
                            http_header_tostr(header, buff_header);
                            mywr = my_write(*fd_to, *ssl_to, "ldldldld",
                                    strlen(buff_header), buff_header,
                                    strlen(chunk_size), chunk_size,
                                    len_gunzip, gunzip,
                                    7, "\r\n0\r\n\r\n");
                        }
                    }
                    else
                    {
                        /* 解压失败 */
                        sprintf(chunk_size, "%x\r\n", len_chunk);
                        http_header_tostr(header, buff_header);
                        mywr = my_write(*fd_to, *ssl_to, "ldldldld",
                                strlen(buff_header), buff_header,
                                strlen(chunk_size), chunk_size,
                                len_chunk, all_chunk,
                                7, "\r\n0\r\n\r\n");
                    }
                    SAFE_FREE(gunzip);
                    SAFE_FREE(all_chunk);
                    if(mywr < 0) {
                        free_http_header(&header);
                        return -1;
                    }
                }
                break;
            }

        case PR_NONE_TXT_LEN:
            {
#ifdef RPS
                printf("%d case %d:\n", getpid(), PR_NONE_TXT_LEN);
#endif
                http_header_tostr(header, buff_header);
                mywr = my_write(*fd_to, *ssl_to, "ld", strlen(buff_header), buff_header);
                if(mywr < 0) {
                    free_http_header(&header);
                    return -1;
                }
#ifdef RPS
                printf("pr_none_txt_len: len = %d\n", len);
#endif
                if(len <= 0) {
                    break;
                }

                ret = read_forward_none_txt(fd_from, ssl_from, *fd_to, *ssl_to, len);
                if(ret <= 0) {
                    free_http_header(&header);
#ifdef RPS
                    printf("read_forward_none_txt %d<= 0", ret);
#endif
                    return ret;
                }
                break;
            }
        case PR_NONE_TXT_CHK:
            {
#ifdef RPS
                printf("%d case %d:\n", getpid(), PR_NONE_TXT_CHK);
#endif
                int left;
                int real_read;
                unsigned int size;
                char chunk_size[64] = {0};
                http_header_tostr(header, buff_header);
                mywr = my_write(*fd_to, *ssl_to, "ld", strlen(buff_header), buff_header);
                if(mywr < 0) {
                    free_http_header(&header);
                    return -1;
                }
                /* 循环转发chunk */
                while(1) {
                    real_read = read_line(fd_from, ssl_from, chunk_size, sizeof(chunk_size));
                    mywr = my_write(*fd_to, *ssl_to, "ld", strlen(chunk_size), chunk_size);
                    if(mywr < 0) {
                        free_http_header(&header);
                        return -1;
                    }
                    erase_nhex(chunk_size);
                    hex2dec(chunk_size, &size);
#ifdef RPS
                    printf("chunk_size = %d\n", size);
#endif
                    left = size + 2;  //2 is for "\r\n", NUM1\r\nBODY1\r\nNUM2\r\nBODY2\r\n 0\r\n\r\n

                    ret = read_forward_none_txt(fd_from, ssl_from, *fd_to, *ssl_to, left);
                    if(ret <= 0) {
                        free_http_header(&header);
#ifdef RPS
                        printf("pr_none_txt_chk: read_forward_none_txt %d <= 0", ret);
#endif
                        return ret;
                    }
                    if(size == 0) {
                        break;
                    }
                }
                break;
            }

        case PR_TXT_NONE:
            {
                /* handle: 对端发送完最后一个报文后关闭写，不管是request还是response */
                /* 可能有body, 全部接收，替换转发 */
                int  ava;
                int  whole;
                int  offset;
                int  real_read;
                unsigned char body[LEN_BUF] = {0};
                whole = 1;
                offset = 0;
                ava = sizeof(body);
#ifdef RPS
                printf("case %d: pr_txt_none, will in while loop\n", PR_TXT_NONE);
#endif
                int cnt = 0;
                /* 如果有body，那么此body定位结束body */
                while(1) {
                    real_read = (proxy==HTTPS)?SSL_read(ssl_from, body + offset, ava):read(fd_from, body + offset, ava);
                    cnt++;
                    if(real_read < 0) {
                        if(proxy == HTTPS) print_ssl_error(ssl_from, real_read, "pr_txt_none");
                        else perror("pr_txt_none: read()");
                        free_http_header(&header);
#ifdef RPS
                        printf("%d case %d: pr_txt_none, will return -1\n", getpid(), PR_TXT_NONE);
#endif
                        return -1;
                    }
                    else if(real_read == 0) {
                        /* 直接读到0，意味着没有body */
                        if(1 == cnt) {
                            http_header_tostr(header, buff_header);
                            mywr = my_write(*fd_to, *ssl_to, "ld", strlen(buff_header), buff_header);
                            if(mywr < 0) {
                                free_http_header(&header);
                                return -1;
                            }
                        }
                        //先替换转发，然后再return.
                        if(offset > 0) {
                            ret = forward_txt_none(*fd_to, *ssl_to, header, body, offset, whole, encd, direction, re);
                            if(ret < 0) {
                                free_http_header(&header);
                                return -1;
                            }
                        }
                        free_http_header(&header);
#ifdef RPS
                        printf("%d case %d: pr_txt_none, will return 0, offset = %d\n", getpid(), PR_TXT_NONE, offset);
#endif
                        return 0;
                    }
                    else {
                        cnt    += 1;
                        ava    -= real_read;
                        offset += real_read;
                        if(ava == 0) {
                            offset = 0;
                            ava = sizeof(body);
                            if(whole == 1) {
                                http_header_tostr(header, buff_header);
                                mywr = my_write(*fd_to, *ssl_to, "ld", strlen(buff_header), buff_header);
                                if(mywr < 0) {
                                    free_http_header(&header);
                                    return -1;
                                }
                            }
                            whole = 0;
                            ret = forward_txt_none(*fd_to, *ssl_to, header, body, offset, whole, encd, direction, re);
                            if(ret < 0) {
                                free_http_header(&header);
                                return -1;
                            }
                            memset(body, 0, sizeof(body));  //unnecessary
                        }
                    }
                }
#ifdef RPS
                printf("%d case %d: pr_txt_none, will break\n", getpid(), PR_TXT_NONE);
#endif
                break;
            }

        case PR_NONE_TXT_NONE:
            {
#ifdef RPS
                printf("%d case %d: pr_none_txt_none\n", getpid(), PR_NONE_TXT_NONE);
#endif
                /* handle: 对端发送完最后一个报文后关闭写，不管是request还是response */
                http_header_tostr(header, buff_header);
                mywr = my_write(*fd_to, *ssl_to, "ld", strlen(buff_header), buff_header);
                if(mywr < 0) {
                    free_http_header(&header);
                    return -1;
                }
                if(IS_REQUEST == req_or_rsp) {
#ifdef RPS
                    printf("PR_NONE_TXT_NONE: is_request\n");
#endif
                    break;
                }
                else if(IS_RESPONSE == req_or_rsp) {
#ifdef RPS
                    printf("PR_NONE_TXT_NONE: is_response\n");
#endif
                    /* 长连接也可能没有http body: 403 Not Modified */
                    break;
                }
                /* 可能有body,接收转发,长度未知 */
                while((ret = read_forward_none_txt(fd_from, ssl_from, *fd_to, *ssl_to, LEN_SSL_RECORD)) == 1) ;
                if(ret <= 0) {
                    free_http_header(&header);
#ifdef RPS
                    printf("pr_none_txt_none: read_forward_none_txt ret %d <= 0\n", ret);
#endif
                    return ret;
                }
                break;
            }

        case PR_NONE:
        default:
            {
#ifdef RPS
                printf("%d case %d: pr_none\n", getpid(), pr);
#endif
                http_header_tostr(header, buff_header);
                mywr = my_write(*fd_to, *ssl_to, "ld", strlen(buff_header), buff_header);
                if(mywr < 0) {
                    free_http_header(&header);
                    return -1;
                }
                break;
            }
    }
    free_http_header(&header);
#ifdef RPS
    printf("==========finish read_process_forward()==========\n");
#endif
    return 1;
}


int read_all_txt_chunk_m(int fd, SSL *ssl, unsigned char **all_chunk, unsigned int *len)
{
#ifdef FUNC
    printf("==========start read_all_txt_chunk_m()==========\n");
#endif
    /* 存入链表 */
    while(1) {
    }
#ifdef FUNC
    printf("==========finish read_all_txt_chunk_m()==========\n");
#endif
    return 0;
}


/* 2018.01.29已做优化，还有隐藏bug */
/* 此函数只用于转发未压缩的chunked文本http报文 */
/* 如果chunk太大，要想办法做限制 */
int read_forward_txt_chunk(int fd_from, SSL *ssl_from, int fd_to, SSL *ssl_to, int encd, int direction, pcre2_code *re)
{
#ifdef FUNC
    printf("==========start read_forward_txt_chunk()==========\n");
#endif
    while(1) {
        int   ret;
        int   tot_len;
        char *new_chunk;
        http_chunk_t chunk;
        ret = read_parse_chk_size_ext_crlf(fd_from, ssl_from, &chunk);
        if(ret <= 0) {
            free_http_chunk(&chunk);
            return ret;
        }
        ret = read_parse_chk_body_crlf(fd_from, ssl_from, &chunk);
        if(ret <= 0) {
            free_http_chunk(&chunk);
            return ret;
        }
        http_chunk_replace(&chunk, direction, re);
        ret = http_chunk_to_buff(&chunk, &new_chunk, &tot_len);
        if(ret <= 0) {
            free_http_chunk(&chunk);
            return ret;
        }
        ret = my_write(fd_to, ssl_to, "ld", tot_len, new_chunk);
        if(ret <= 0) {
            return -1;
        }
        int size = chunk.chk_size;
        free_http_chunk(&chunk);
        SAFE_FREE(new_chunk);
        if(size <= 0) {
            break;
        }
    }
        
#ifdef FUNC
    printf("==========finish read_forward_txt_chunk()==========\n");
#endif
    return 0;
}


int read_parse_chk_size_ext_crlf(int fd, SSL* ssl, http_chunk_t *chunk)
{
    int ret;
    char line[LEN_LINE] = {0};
    ret = read_line(fd, ssl, line, sizeof(line));
    if(ret <=0) {
        return ret;
    }
    /* size ext crlf */
    /* ext: 
     * "ext_name":"ext_value"
     *
     */
    char size[64] = {0};
    ret = sscanf(line, "%[0-9a-zA-Z]", size);
    if(1 != ret) {
        printf("chk_size error\n");
        return -1;
    }
    chunk->chk_size = hex2dec(size); 

    char *lf = strstr(line, "\n");
    char *crlf = strstr(line, "\r\n");
    crlf = crlf?crlf:lf;
    if(NULL == crlf) {
        printf("chk_crlf error\n");
        return -1;
    }
    if(strlen(crlf) > sizeof(chunk->chk_crlf)-1) {
        printf("chk_crlf length over 2, [%s]\n", crlf);
        return -1;
    }
    strcpy(chunk->chk_crlf, crlf);
    
    char *split = strchr(line, ';');
    if(split) {
        chunk->chk_ext = (char *)calloc(1, crlf-split+1);
        strncpy(chunk->chk_ext, split, crlf-split);
    }
    return 0;
}


int read_parse_chk_body_crlf(int fd, SSL *ssl, http_chunk_t *chunk)
{
    /* 非trailer */
    /* 可能是压缩过的内容:w */
    if(chunk->chk_size > 0) {
        int ret1, ret2;
        chunk->trl_size = 0;
        chunk->chk_body = (char *)calloc(1, chunk->chk_size);
        ret1 = readn(fd, ssl, chunk->chk_body, chunk->chunk_size);
        if(ret1 <=0) {
            return ret1;
        }
        if(ret1 != chunk->chk_size) {
            printf("chunk body: should read %d, actual read %d\n", chunk->chk_size, ret1);
        }
        ret2 = read_line(fd, ssl, chunk->body_crlf, sizeof(chunk->body_crlf));
        if(ret2 <=0) {
            return ret2;
        }
        return ret1;
    }
    /* trailer */
    else {
        int ret;
        int tot = 0;
        char line[LEN_LINE] = {0};
        while((ret = read_line(fd, ssl, sizeof(line))) > 0){
            if(is_empty_line(line)) {
                chunk->trl_size = tot;
                memcpy(chunk->body_crlf, line, ret);
                break;
            }
            else{
                chunk->trailer = realloc(chunk->trailer, tot+ret);
                memcpy(chunk->trailer+tot, line, ret);
                tot += ret;
            }
            memset(line, 0, sizeof(line));
        }
    }
}

int is_empty_line(const char *line)
{
    if(NULL == line) {
        return 0;
    }
    int len = strlen(line);
    if(1 == len && line[0] == '\n'){
        return 1;
    }
    else if(2 == len && line[0] == '\r' && line[1] == '\n') {
        return 1;
    }
    else {
        return 0;
    }
}


int http_chunk_replace(http_chunk_t *chunk, int direction, pcre2_code *re)
{
    PCRE2_SPTR new = replace_content_default_m(chunk->body, direction, re);
    if(new) {
        SAFE_FREE(chunk->body);
        chunk->body = (char *)new;
        chun->chk_size = strlen(new);
    }
    return 0;
}

int http_chunk_to_buff(http_chunk_t *chunk, char **buf, int *len)
{
    /* 32位操作系统十六进制字符串最长8 */
    char size[64] = {0};
    sprintf(size, "%x", chunk->chk_size);
    *len = strlen(size) + (chunk->chk_ext?strlen(chunk->chk_ext):0) +
        strlen(chunk->chk_crlf) + chunk->chk_size + chunk->trl_size +
        strlen(chunk->body_crlf);
    *buf = (char *)calloc(1, *len);
    if(NULL == *buf) {
        perror("calloc in http_chunk_to_buf");
        return -1;
    }
    int offset = 0; 
    memcpy(*buf + offset, size, strlen(size));
    offset += strlen(size);
    if(chunk->chk_ext) {
        memcpy(*buf + offset, chunk->chk_ext, strlen(chunk->chk_ext));
        offset += strlen(chunk->chk_ext);
    }
    memcpy(*buf + offset, chunk->chk_crlf, strlen(chunk->chk_crlf));
    offset += strlen(chunk->chk_crlf);
    if(chunk->chk_size > 0) {
        memcpy(*buf + offset, chunk->body, chunk->chk_size);
        offset += chunk->chk_size;
    }
    if(chunk->trl_size > 0) {
        memcpy(*buf + offset, chunk->trailer, chunk->trl_size);
        offset += chunk->trl_size;
    }
    memcpy(*buf + offset, chunk->body_crlf, strlen(chunk->body_crlf));
    offset += strlen(chunk->body_crlf);
    return 0;
}

/*出错时，不由此函数来释放header*/
int forward_txt_none(int fd, SSL *ssl, http_header_t *header, unsigned char *body, int len, int whole, int encd, int direction, pcre2_code *re)
{
#ifdef FUNC
    printf("==========start forward_txt_none()==========\n");
#endif
    int ret;
    char *gunzip;
    unsigned int len_gunzip;
    char buff_header[LEN_HEADER] = {0};
    PCRE2_SPTR new_body = NULL;
    int mywr;
#ifdef DEBUG
    printf("len = %d, whole = %d, encd = %d\n", len, whole, encd);
#endif

    /* 不完整的包不用转header */
    if(whole != 1) {
        /*  不完整的压缩包，直接转 */
        if(encd == ENCD_GZIP) {
#ifdef DEBUG
            printf("not whole, direct forwrad, gunzip\n");
#endif
            mywr = my_write(fd, ssl, "ld", len, body);
            if(mywr < 0) {
                return -1;
            }
        }
        else {
            new_body = replace_content_default_m((char *)body, direction, re);
            if(new_body) {
#ifdef DEBUG
                printf("not whole, forward replace\n");
#endif
                mywr = my_write(fd, ssl, "ld", strlen((char *)new_body), new_body);
                SAFE_FREE(new_body);
                if(mywr < 0) {
                    return -1;
                }
            }
            else {
#ifdef DEBUG
                printf("not whole, direct forwrad txt no replace\n");
#endif
                mywr = my_write(fd, ssl, "ld", len, body);
                if(mywr < 0) {
                    return -1;
                }
            }
        }
    }

    /* 完整的包还要转一下header */
    else {
        if(encd == ENCD_GZIP) {
            /* 整包就解压 */
            ret = get_gunzip(body, len, &gunzip, &len_gunzip);
            if(ret < 0) {
#ifdef DEBUG
                printf("whole, direct forwrad, cannot gunzip\n");
#endif
                http_header_tostr(header, buff_header);
                mywr = my_write(fd, ssl, "ldld", strlen(buff_header), buff_header, len, body); 
            }
            else {
                /* need to rewrite_encd */
                new_body = replace_content_default_m(gunzip, direction, re);
                if(new_body) {
#ifdef DEBUG
                    printf("whole, forward new_body");
#endif
                    rewrite_encd(&(header->head), ENCD2FLATE);
                    http_header_tostr(header, buff_header);
                    mywr = my_write(fd, ssl, "ldld", strlen(buff_header), buff_header, strlen((char *)new_body), new_body);
                    SAFE_FREE(new_body);
                }
                else { 
#ifdef DEBUG
                    printf("whole, direct forwrad, cannot replace\n");
#endif
                    http_header_tostr(header, buff_header);
                    mywr = my_write(fd, ssl, "ldld", strlen(buff_header), buff_header, len, body); 
                }
            }
            SAFE_FREE(gunzip);
            SAFE_FREE(new_body);
            if(mywr < 0) {
                return -1;
            }
        }

        /* 整包未压缩 */
        else {
            http_header_tostr(header, buff_header);
            new_body = replace_content_default_m((char *)body, direction, re);
            if(new_body) {
#ifdef DEBUG
                printf("whole, forward new_body");
#endif
                mywr = my_write(fd, ssl, "ldld", strlen(buff_header), buff_header, strlen((char *)new_body), new_body);
                SAFE_FREE(new_body);
                if(mywr < 0) {
                    return -1;
                }
            }
            else {
#ifdef DEBUG
                printf("whole, direct forwrad, cannot replace\n");
#endif
                mywr = my_write(fd, ssl, "ldld", strlen(buff_header), buff_header, len, body);
                if(mywr < 0) {
                    return -1;
                }
            }
        }
    }

#ifdef FUNC
    printf("==========finish forward_txt_none()==========\n");
#endif
    return 1;
}

/* 
 * return :
 *      1 : 读并转发完成
 *      0 : 读到结束,(非信号打断错误) 
 *      -1: 读到错误 
 */
int read_forward_none_txt(int fd_from, SSL *ssl_from, int fd_to, SSL *ssl_to, int len_body)
{
#ifdef FUNC
    printf("==========start read_forward_none_txt==========\n");
#endif
    int left;
    int rd;
    int mywr;
    int real_read;
    int tot = 0;
    left = len_body;
    char body[LEN_SSL_RECORD] = {0};
    while(left > 0) {
        /* 读取大小要限制在缓冲区的范围内 */
        rd = left<=sizeof(body)?left:sizeof(body);
        real_read = (proxy==HTTPS)?SSL_read(ssl_from, body, rd):read(fd_from, body, rd);
        if(real_read < 0) {
            if(proxy == HTTPS) print_ssl_error(ssl_from, real_read, "read_forward_none_txt");
            else perror("read()");

            if(errno == EINTR) {
                continue;
            }
            else {
                return -1;
            }
        }
        else if(real_read == 0) {
            if(proxy == HTTPS) print_ssl_error(ssl_from, real_read, "read_forward_none_txt");
            break;
        }
        else {
            left -= real_read;
            tot  += real_read;
            mywr = my_write(fd_to, ssl_to, "ld", real_read, body);
            if(mywr < 0) {
                return -1;
            }
        }
    }
#ifdef FUNC
    printf("==========finish read_forward_none_txt==========\n");
#endif
    return tot;
}


int create_proxy_server(char *host, short l_port, int listen_num)
{
#ifdef FUNC
    printf("==========start create_proxy_server()==========\n");
#endif
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0)
        err_quit("socket");
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));

    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(l_port);
    if(NULL == host) {
        local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } 
    inet_pton(AF_INET, host, &local_addr.sin_addr.s_addr);
    if(bind(fd, (struct sockaddr *) &local_addr, sizeof(local_addr)) < 0)
        err_quit("bind");
    if(listen(fd, listen_num) < 0)
        err_quit("listen");
#ifdef FUNC
    printf("==========finish create_proxyy_server()==========\n");
#endif
    return fd;
}

int create_real_server(const char *host, short port)
{
    /* 建立和服务器的连接, 使用select超时连接 */
#ifdef FUNC
    printf("==========start create_real_server()==========\n");
#endif
//#ifdef DEBUG
    printf("create_real_server host=%s, port=%d\n", host, port);
//#endif
    int s_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(s_fd < 0) {
        perror("socket()");
        return -1;
    }
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(host);

    if(connect(s_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        syslog(LOG_INFO, "cannot create connect with %s:%d", host, port);
        return -1;
    }
//#ifdef DEBUG
    printf("connected to %s:%d\n", host, port);
//#endif
#ifdef FUNC
    printf("==========finish create_real_server()==========\n");
#endif
    return s_fd;
}

int create_real_server_nonblock(const char *host, short port, int sec)
{
    /* 建立和服务器的连接 */
#ifdef FUNC
    printf("==========start create_real_server_nonblock()==========\n");
#endif
    int s_fd = socket(AF_INET, SOCK_STREAM, 0);

    if(s_fd < 0) {
        perror("socket()");
        return -1;
    }
    /* 设置非阻塞 */
    int flags = fcntl(s_fd, F_GETFL, 0);
    if(flags < 0)
    {
        perror("fcntl f_get");
        goto end;
    }
    if(fcntl(s_fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        perror("fcntl f_set");
        goto end;
    }

    struct sockaddr_in server_addr;
    struct hostent *server;
    if((server = gethostbyname(host)) == NULL)
    {
        printf("\033[31m");
        printf("gethostbyname [%s] error, h_error=%d, %s\n", host, h_errno, hstrerror(h_errno));
        printf("\033[0m");
        goto end;
    }
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    /* inet_pton(AF_INET, host, &(server_addr.sin_addr.s_addr)); */
    memcpy(&(server_addr.sin_addr.s_addr), server->h_addr, server->h_length);
//#ifdef DEBUG
    char ip[16] = {0};
    printf("%s <--> %s port=%d\n", host, inet_ntop(AF_INET, server->h_addr, ip, sizeof(ip)), port);
//#endif
    if(connect(s_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0)
    {
        if(errno != EINPROGRESS)
        {
//#ifdef DEBUG
            printf("connect err\n");
//#endif
            goto end;
        }
    }
    fd_set rset, wset;
    FD_ZERO(&rset);
    FD_ZERO(&wset);
    FD_SET(s_fd, &rset);
    FD_SET(s_fd, &wset);
    struct timeval tout;
    tout.tv_sec = sec > 0 ? sec : 0;
    tout.tv_usec = 0;
    int ret = select(s_fd + 1, &rset, &wset, NULL, tout.tv_sec > 0 ? &tout : NULL);
    if(ret > 0)
    {
        if(FD_ISSET(s_fd, &rset) || FD_ISSET(s_fd, &wset))
        {
            int error = 0;
            unsigned int len = sizeof(error);
            if(getsockopt(s_fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
            {
                perror("getsockopt");
                goto end;
            }
            else
            {
                /* 改回非阻塞 */
                if(fcntl(s_fd, F_SETFL, flags) < 0)
                    goto end;
                return s_fd;
            }
        }
    }
    else if(ret == 0)
    {
#ifdef DEBUG
        printf("select timeout!\n");
#endif
        goto end;
    }
    else
    {
        perror("select");
        goto end;
    }

end:
    close(s_fd);
#ifdef FUNC
    printf("==========finish create_real_server_nonblock()==========\n");
#endif
    return -1;
}


PCRE2_SPTR replace_content_default_m(char *old, int direction, pcre2_code *re)
{
#ifdef FUNC
    printf("==========start replace_content_default_m()==========\n");
#endif
#ifdef TIME_COST
    struct timeval strt;
    struct timeval end;
    gettimeofday(&strt, NULL);
#endif
    //printf("old = [%s]\n", old);
    PCRE2_SPTR new = NULL;
    struct list_head *head = get_list_substring_compiled_code((PCRE2_SPTR) old, re);
    if(head == NULL) {
        return NULL;
    }

    printf("direction=%d\n", direction);
    if(direction == REQUEST)
        pad_list_rplstr_malloc(head, pad_list_rplstr_remap_table_req_m, remap_table);
    else if(direction == RESPONSE)
        pad_list_rplstr_malloc(head, pad_list_rplstr_remap_table_rsp_m, remap_table);
    else if(direction == LAN2WAN)
        pad_list_rplstr_malloc(head, pad_list_rplstr_lan2wan, remap_table);
    else if(direction == WAN2LAN)
        pad_list_rplstr_malloc(head, pad_list_rplstr_wan2lan, remap_table);

    new = replace_all_default_malloc((PCRE2_SPTR) old, head);
    free_list_substring(&head);
#ifdef FUNC
    printf("==========finish replace_content_default_m（）==========\n");
#endif
#ifdef TIME_COST
    gettimeofday(&end, NULL);
    printf("execute replace_content_default_m use time: start=%lds %ldms, end in %lds %ldms\n", strt.tv_sec, strt.tv_usec, end.tv_sec, end.tv_usec);
#endif
    if(NULL == new)
        return NULL;
    return new;
}


int rewrite_url(char *url, int max, pcre2_code *re, int direction)
{
    /* 替换ip */
#ifdef FUNC
    printf("==========start rewrite_url()==========\n");
#endif

    /* 重写格式 */
    /* url中的协议名和域名部分不区分大小写, 路径区分大小写 */
    int len;
    char *start = url;
    while(*start == ' ') start++;
    char *p = strcasestr(start, "http://");
    /* 如果GET提交表单中含有http://，不作数 */
    if(p && p==start) {
        char *p1 = strchr(p + 7, '/');
        if(p1) {
            /* http://192.168.1.33/setup.cgi?ip1=192.168.1.33&ip2=192.168.1.22  --> /setup.cgi?ip1=192.168.1.33&ip2=192.168.1.22 */
            len = strlen(p1);
            memmove(url, p1, strlen(p1));
            *(url + len) = '\0';
        }
        else {
            /* http://192.168.1.33 --> / */
            memset(url, 0, LEN_URL);
            strcpy(url, "/");
        }
    }

    PCRE2_SPTR subject = replace_content_default_m(url, direction, re);
    if(subject) {
        len = strlen((char *)subject);
        if(len < max-1) {
            memset(url, 0, max);
            memmove(url, (char *)subject, len);
            *(url + len) = '\0';
        }
        else{
            printf("替换后的url长度过长");
            syslog(LOG_INFO, "替换后的url长度过长");
        }
        SAFE_FREE(subject);
    }
    //printf("after rewrite url=%s\n", req->url);
#ifdef FUNC
    printf("==========finish rewrite_url()==========\n");
#endif
    return 0;
}


int replace_field(char *field_value, int direction, pcre2_code *re)
{
#ifdef FUNC
    printf("==========start replace_field()==========\n");
#endif
    PCRE2_SPTR subject = (PCRE2_SPTR) field_value;
    struct list_head *head = get_list_substring_compiled_code(subject, re);
    if(head == NULL)
        return -1;

    if(direction == REQUEST)
        pad_list_rplstr_malloc(head, pad_list_rplstr_remap_table_req_m, remap_table);
    else if(direction == RESPONSE)
        pad_list_rplstr_malloc(head, pad_list_rplstr_remap_table_rsp_m, remap_table);
    else if(direction == LAN2WAN)
        pad_list_rplstr_malloc(head, pad_list_rplstr_lan2wan, remap_table);
    else if(direction == WAN2LAN)
        pad_list_rplstr_malloc(head, pad_list_rplstr_wan2lan, remap_table);
    PCRE2_SPTR new_subject = replace_all_default_malloc(subject, head);
    if(NULL == new_subject)
    {
        free_list_substring(&head);
        return -1;
    }
    memset(field_value, 0, LEN_FIELD_VALUE);
    strcpy(field_value, (char *) new_subject);
    free_list_substring(&head);
    SAFE_FREE(new_subject);
#ifdef FUNC
    printf("==========finish replace_field()==========\n");
#endif
    return 0;
}

/* 
 * 遍历链表，每一个节点做匹配和替换 
 * 目前已知包含ip地址的域有Host, Origin, Referer, Location
 */
int replace_http_header(http_header_t *header, pcre2_code *re, int direction)
{
#ifdef FUNC
    printf("==========start replace_http_header()==========\n");
#endif
#ifdef TIME_COST
    struct timeval strt;
    struct timeval end;
    gettimeofday(&strt, NULL);
#endif
    int req_or_rsp = is_http_req_rsp(header);
    /* replace url */
    if(req_or_rsp == IS_REQUEST) {
        rewrite_url(header->url, sizeof(header->url), re, direction);
    }

    struct list_head *head = &(header->head);
    struct list_head *pos;
    list_for_each(pos, head)
    {
        http_field_t *field = list_entry(pos, http_field_t, list);

        if(strcasestr(field->key, "Host"))
        {
#ifdef DEBUG
            printf("<%s>\n", field->key);
#endif
            replace_field(field->value, direction, re);
        }
        if(strcasestr(field->key, "Referer"))
        {
#ifdef DEBUG
            printf("<%s>\n", field->key);
#endif
            replace_field(field->value, direction, re);
        }
        if(strcasestr(field->key, "Origin"))
        {
#ifdef DEBUG
            printf("<%s>\n", field->key);
#endif
            replace_field(field->value, direction, re);
        }
        if(strcasestr(field->key, "Location"))
        {
#ifdef DEBUG
            printf("<%s>\n", field->key);
#endif
            replace_field(field->value, direction, re);
        }
    }
#ifdef FUNC
    printf("==========finish replace_http_header()==========\n");
#endif
#ifdef TIME_COST
    gettimeofday(&end, NULL);
    printf("execute replace_http_header use time: start=%lds %ldms, end in %lds %ldms\n", strt.tv_sec, strt.tv_usec, end.tv_sec, end.tv_usec);
#endif
    return 0;
}

int get_gunzip(unsigned char *src, unsigned int len_s, char **dst, unsigned int *len_d)
{
#ifdef FUNC
    printf("==========start get_gunzip==========\n");
#endif
    int ret;
    srandom(time(NULL));
    char tmp[64] = {0};
    char tmp_gz[64] = {0};
    char cmd[256] = {0};
    long r1 = random();
    long r2 = random();
    ret = sprintf(tmp, "/tmp/%ld%ld", r1, r2);
    ret = sprintf(tmp_gz, "%s.gz", tmp);
    int fd_s = open(tmp_gz, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if(fd_s < 0)
        return -1;
    if(write(fd_s, src, len_s) != len_s)
    {
        close(fd_s);
        unlink(tmp_gz);
        return -1;
    }

    close(fd_s);
    sprintf(cmd, "gunzip %s", tmp_gz);                       
    sighandler_t old_handler = signal(SIGCHLD, SIG_DFL);
    ret = system(cmd);
    signal(SIGCHLD, old_handler);
    unlink(tmp_gz);                                          /* not necessary */

    int fd_d = open(tmp, O_RDONLY);
    if(fd_d < 0)
        return -1;
    *len_d = lseek(fd_d, 0, SEEK_END);
    lseek(fd_d, 0, SEEK_SET);
    *dst = (char *)calloc(1, *len_d);
    if(NULL == *dst)
    {
        perror("malloc");
        close(fd_d);
        unlink(tmp); 
        return -1;
    }
    if(read(fd_d, *dst, *len_d) != *len_d)
    {
        SAFE_FREE(*dst);
        close(fd_d);
        unlink(tmp); 
        return -1;
    }
    close(fd_d);
    unlink(tmp);
#ifdef FUNC
    printf("==========finish get_gunzip()==========\n");
#endif
    return 0;
}

#if 0
#ifdef OpenWRT
int get_gunzip(unsigned char *src, unsigned int len_s, char **dst, unsigned int *len_d)
{
#ifdef FUNC
    printf("==========get_gunzip==========\n");
#endif
    int ret;
    ret = http_gunzip(src, len_s, dst, len_d, GZIP2FLATE);
#ifdef DEBUG
    printf("ret = %d, len_s = %d, *len_d = %d *dst=%p\n", ret == Z_OK?0:-1, len_s, *len_d, *dst);
    printf("gunzip = [%s]\n", *dst);
#endif
#ifdef FUNC
    printf("==========get_gunzip==========\n");
#endif
    return ret == Z_OK?0:-1;
}

int http_gunzip(unsigned char *source, unsigned int s_len, unsigned char **dest, unsigned int *d_len, int gzip)
{ 
    /* 这段代码暂时还是有问题 */
    int ret; 
    unsigned have; 
    z_stream strm; 
    unsigned char out[CHUNK]; 
    int totalsize = 0; 

    /* both inflateInit and inflateInit2　require */ 
    strm.zalloc = Z_NULL;
    strm.zfree  = Z_NULL;
    strm.opaque = Z_NULL;

    /* inflateInit2() requires */
    strm.avail_in = 0; 
    strm.next_in = Z_NULL;

    if(gzip) 
        ret = inflateInit2(&strm, 47);    /* don't know why must be 47 */ 
    else 
        ret = inflateInit(&strm);

    if (ret != Z_OK)
        return ret; 

    strm.avail_in = s_len; 
    strm.next_in = source; 

    /* run inflate() on input until output buffer not full */ 
    do { 
        strm.avail_out = CHUNK; 
        strm.next_out = out; 
        ret = inflate(&strm, Z_NO_FLUSH); 
        assert(ret != Z_STREAM_ERROR);  /* state not clobbered */ 

        switch (ret) { 
            case Z_NEED_DICT: 
                ret = Z_DATA_ERROR;     // and fall through
            case Z_DATA_ERROR: 
            case Z_MEM_ERROR: 
                inflateEnd(&strm); 
                return ret; 
        } 

        have = CHUNK - strm.avail_out; 
        totalsize += have; 
        *dest = realloc(*dest, totalsize);
        printf("*dest=%p\n", *dest);
        memcpy(*dest + totalsize - have, out, have); 
    } while (strm.avail_out == 0);
    //printf("*dest=%p\n", *dest);
    *d_len  = totalsize;

    /* clean up and return */ 
    (void)inflateEnd(&strm);
    printf("*dest=%p\n", *dest);
    return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
}
#endif
#endif
