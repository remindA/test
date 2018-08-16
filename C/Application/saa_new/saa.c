/*
 * =====================================================================================
 *
 *       Filename:  saa.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年07月27日 17时30分52秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/select.h>
#include <fcntl.h>
#include <openssl/md5.h>
#include <openssl/crypto.h>
#include <signal.h>
#include <errno.h>
#include "protocol.h"
#include "config.h"
#include "utils_net.h"
#include "ipset.h"

void do_update(struct list_head *head_yes, struct list_head *head_no);
void saa_flush_list(struct list_head *head);
void generate_auth_code(const char *mach_code, char *auth_code);
void update_handle(int signo);
void process_access(struct list_head *head_yes, struct list_head *head_no);
void process_message(int fd, struct list_head *head_yes, struct list_head *head_no);
void free_saa_pkt(saa_pkt_t *pkt);
void saa_response(int fd, int cmd, saa_entry_t *match);
int saa_process_request(int fd, saa_pkt_t *pkt, struct list_head *head_yes, struct list_head *head_no, saa_entry_t **match);
void parse_auth_req(saa_entry_t *entry, saa_pkt_t *pkt);
void parse_access_req(saa_entry_t *entry, saa_pkt_t *pkt);
void parse_exit_req(saa_entry_t *entry, saa_pkt_t *pkt);
int deal_auth_req(saa_entry_t *entry, struct list_head *head_yes, struct list_head *head_no, saa_entry_t **match);
int deal_access_req(saa_entry_t *entry, struct list_head *head_yes, struct list_head *head_no, saa_entry_t **match);
int deal_exit_req(saa_entry_t *entry, struct list_head *head_yes, struct list_head *head_no, saa_entry_t **match);
void mac_to_str(unsigned char *mac, char *mac_str);
saa_entry_t *find_match_mach(struct list_head *head, saa_entry_t *entry);
saa_entry_t *find_match_auth(struct list_head *head, saa_entry_t *entry);

int update = 0;

int main(int argc, char **argv)
{
    int ret;
    struct list_head head_yes;
    struct list_head head_no;
    init_list_head(&head_yes);
    init_list_head(&head_no);
    signal(SIGUSR1, update_handle);

    /* start: all clients cannot access */
    int fd = sock_create_tcp(server_ip, server_port, MAX_CLIENT_NUM);
    if(fd < 0) {
        return 0;
    }

    int i;
    fd_set rset;
    int fd_max = -1;
    struct timeval = tout;
    int c_fd[MAX_CLIENT_NUM] = {0};
    update = 1;
    while(1) {
        while(update > 0) {
            update--;
            do_update();
        }

        FD_ZERO(&rset);
        FD_SET(fd, &rset);
        fd_max = fd>fd_max?fd:fd_max;
        for(i = 0; i < MAX_CLIENT_NUM; i++) {
            if(c_fd[i] > 0) {
                FD_SET(c_fd[i], &rset);
                fd_max = c_fd[i]>fd_max?c_fd[i]:fd_max;
            }
        }
        tout.tc_sec = 3;
        tout.tc_usec = 0;
        ret = select(fd_max+1, &rset, NULL, NULL, &tout);
        if(ret < 0) {
            if(errno == EINTR) {
                continue; 
            }
            perror("select()");
        }
        else if(ret == 0) {
            ;
        }
        else {
            if(FD_ISSET(fd, &rset)) {
                for(i = 0; i < MAX_CLIENT_NUM; i++) {
                    if(c_fd[i] <= 0) {
                        struct sockaddr_in addr;
                        socklen_t addrlen = sizeof(addr);
                        c_fd[i] = accept(fd, (struct sockaddr *)&addr, &addrlen);
                        if(c_fd[i] < 0) {
                            perror("accept()");
                        }
                    }
                }
            }
            for(i = 0; i < MAX_CLIENT_NUM; i++) {
                if(c_fd[i] > 0 && FD_ISSET(c_fd[i], &rset)) {
                    process_message(c_fd[i], &head_yes, &head_no);
                    close(c_fd[i]);
                    c_fd[i] = -1;
                }
            }
        }
        process_access(&head_yes, &head_no);

        update_unauth_file(head_no, config_file_no); 
    }
}

void do_update(struct list_head *head_yes, struct list_head *head_no)
{
    /* read config_file_yes, caculate auth_code */
    saa_rules_flush();
    saa_flush_list(head_no);
    saa_flush_list(head_yes);
    read_config_yes(config_file_yes, head_yes);
    struct list_head *pos;
    list_for_each(pos, head_yes) {
        saa_entry_t *entry = list_entry(pos, saa_entry_t, list);
        generate_auth_code(entry->mach_code, entry->auth_code);
    }
    /* read config_file_no */
    read_config_no(config_file_no, head_no);
    process_access(head_yes, head_no);
}

void saa_flush_list(struct list_head *head)
{
    struct list_head *pos = head->next;
    while(pos != head) {
        saa_entry_t *entry = list_entry(pos, saa_entry_t, list);
        pos = pos->next;
        list_del(&(entry->list));
        SAFE_FREE(entry);
    }
}

void generate_auth_code(const char *mach_code, char *auth_code)
{
    MD5_CTX ctx;
    unsigned char md[16];
    MD5_Init(&ctx);
    MD5_Update(&ctx, mach_code, strlen(mach_code));
    MD5_Final(md, &ctx);
    char tmp[16]   = {0};
    char tmp_md5[128] = {0};
    int i = 0;
    for(i = 0; i < 16; i++) {
        memset(tmp, 0, sizeof(tmp));
        sprintf(tmp, "%02X", md[i]);
        strcat(tmp_md5, tmp);
    }
    strcat(tmp_md5, "saa");

    MD5_Init(&ctx);
    MD5_Update(&ctx, tmp_md5, strlen(tmp_md5));
    MD5_Final(md, &ctx);
    for(i = 0; i < 16; i++) {
        memset(tmp, 0, sizeof(tmp));
        sprintf(tmp, "%02X", md[i]);
        strcat(md5_str, tmp);
    }
    strncpy(auth_code, md5_str, LEN_AUTH_CODE);
}

void process_access(struct list_head *head_yes, struct list_head *head_no)
{
    saa_entry_t *entry;
    struct list_head *pos;
    list_for_each(pos, head_yes) {
        entry = list_entry(pos, saa_entry_t, list);
        if(time(NULL) - entry->online_tstamp > ACCESS_TIMEOUT ||
            entry->online_tstamp <= 0) {
            entry->access_switch = ACCESS_OFF;
            saa_rules_del(inet_ntoa(entry->ipaddr, NULL);
        }
        else {
            entry->access_switch = ACCESS_ON;
            saa_rules_add(inet_ntoa(entry->ipaddr, NULL); 
        }
    }
    pos = head_no->next;
    while(pos != head_no) {
        entry = list_entry(pos, saa_entry_t, list);
        pos = pos->next;
        saa_rules_del(inet_ntoa(entry->ipaddr, NULL));
        // 长时间没有发auth req
        if(time(NULL) - entry->online_tstamp > AUTH_TIMEOUT) {
            list_del(&(entry->list));
            SAFE_FREE(entry);
        }
    }
}


void update_handle(int signo)
{
    update++;
}

/*
 * client, short connection
 * no need to use FSM
 * when delays is too long and tcp push is devided into mutipule frame,
 * process_message will failed
 */
void process_message(int fd, struct list_head *head_yes, struct list_head *head_no)
{
    int ret;
    saa_pkt_t pkt;
    char buff[LEN_SAA_PKT_MAX] = {0};
    /* read */
    ret = read(fd, buff, sizeof(buff));
    if(ret < 0) {
        if(errno == EINTR) {
            continue;
        }
        perror("read()");
        return;
    }
    else if(ret == 0) {
        return;
    }

    /* parse */
    if(saa_parse_pkt(&pkt, buff, ret) < 0) {
        return;
    }

    /* process: add\del\already exist */
    saa_entry_t *match = NULL;
    ret = saa_process_request(fd, &pkt, head_yes, head_no, &match);

    /* response */
    saa_response(fd, ret, match);
}

int saa_parse_pkt(saa_pkt_t *pkt, char *buff, int len)
{
    if(len < sizeof(saa_hdr_t) + sizeof(tail)) {
        return ERR_BAD_PKT;
    }
    memcpy(&(pkt->hdr), buff, sizeof(pkt->hdr));
    pkt->hdr.head = ntohs(pkt->hdr.head);
    pkt->hdr.version = ntohs(pkt->hdr.version);
    pkt->hdr.reserve = ntohs(pkt->hdr.reserve);
    pkt.hdr.dlen = ntohs(pkt->hdr.dlen);
    if(len != (sizeof(pkt->hdr)+pkt->hdr.dlen+sizeof(pkt->tail))) {
        return ERR_BAD_PKT;
    }
    pkt->data = buff+sizeof(pkt->hdr);
    return 0;
}

void free_saa_pkt(saa_pkt_t *pkt)
{
    if(pkt->data) {
        free(pkt->data);
        pkt->data = NULL;
    }
}

void saa_response(int fd, int cmd, saa_entry_t *match)
{
    saa_pkt_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.hdr.head = htons(VALUE_HEAD);
    pkt.hdr.version = htons(VALUE_VERSION1);
    pkt.hdr.reserve = htons(VALUE_RESERVE);
    pkt.hdr.cmd = htons(cmd);
    pkt.tail = htons(VALUE_TAIL);
    switch(cmd) {
    case CMD_RSP_UNAUTH:
    case CMD_RSP_ACCESS_SUCCESS:
    case CMD_RSP_ACCESS_FAILURE:
    case CMD_RSP_EXIST:
        pkt.hdr.dlen = 0;
        pkt.data = NULL;
        break;
    case CMD_RSP_AUTHED:
        {
        /* 需要数据 */
        pkt.hdr.dlen = htons(LEN_AUTHED_RSP);
        pkt.data = (unsigned char *)calloc(1, pkt.hdr.dlen);
        if(NULL == pkt.data) {
            return;
        }
        int off = 0;
        memcpy(data+off, match->mach_code, LEN_MACH_CODE);
        off += LEN_MACH_CODE;
        memcpy(data+off, match->auth_code, LEN_AUTH_CODE);
        break;
        }
    default:
        return;
    }
    int off = 0;
    unsigned char buff[1024] = {0};
    memcpy(buff+off, &(pkt.hdr), sizeof(pkt.hdr));
    off += sizeof(pkt.hdr);
    if(pkt.hdr.dlen > 0) {
        memcpy(buff+off, pkt.data, pkt.hdr.dlen);
        off += pkt.hdr.dlen;
    }
    memcpy(buff+off, &(pkt.tail), sizeof(pkt.tail));
    off += sizeof(pkt.tail);
    write(fd, buff, off);
    free_saa_pkt(&pkt);
}

int saa_process_request(int fd, saa_pkt_t *pkt, struct list_head *head_yes, struct list_head *head_no, saa_entry_t **match)
{
    /* parse saa entry */
    char ip_str[LEN_IP_STR] = {0};
    saa_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry->online_tstamp = time(NULL);
    sock_get_peeraddr(fd, ip_str, NULL);
    inet_aton(ip_str, &(entry->ipaddr));
    /* add\del\exist */
    switch(pkt->hdr.cmd) {
    case CMD_AUTH_REQ:
        if(pkt->hdr.dlen != LEN_AUTH_REQ) {
            return ERR_BAD_PKT;
        }
        parse_auth_req(&entry, pkt);
        return deal_auth_req(&entry, head_yes, head_no, match);
    case CMD_ACCESS_REQ:
        if(pkt->hdr.dlen != LEN_ACCESS_REQ) {
            return ERR_BAD_PKT;
        }
        parse_access_req(&entry, pkt);
        return deal_access_req(&entry, head_yes, head_no, match);
    case CMD_EXIT_REQ:
        if(pkt->hdr.dlen != LEN_EXIT_REQ) {
            return ERR_BAD_PKT;
        }
        parse_exit_req(&entry, head_yes, head_no);
        return deal_exit_req(&entry, head_yes, head_no, match);
    default:
        return ERR_BAD_PKT;
    }
}

void mac_to_str(unsigned char *mac, char *mac_str)
{
    sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void parse_auth_req(saa_entry_t *entry, saa_pkt_t *pkt)
{
    int off = 0;
    unsigned char mac[LEN_MAC] = {0};
    memcpy(mac, pkt->data+off, sizeof(mac));
    off += sizeof(entry->mac);
    mac_to_str(mac, entry->mac);
    memcpy(entry->mach_code, pkt->data+off, sizeof(entry->mach_code));
    memset(entry->auth_code, 0, sizeof(entry->auth_code));
    entry->access_switch = ACCESS_OFF;
}


void parse_access_req(saa_entry_t *entry, saa_pkt_t *pkt)
{
    int off = 0;
    unsigned char mac[LEN_MAC] = {0};
    memcpy(mac, pkt->data+off, sizeof(mac));
    off += sizeof(entry->mac);
    mac_to_str(mac, entry->mac);
    memcpy(entry->mach_code, pkt->data, sizeof(entry->mach_code));
    off += sizeof(entry->mach_code);
    memcpy(entry->auth_code, pkt->data+off, sizeof(entry->auth_code));
}

void parse_exit_req(saa_entry_t *entry, saa_pkt_t *pkt)
{
    parse_access_req(entry, pkt);
}

saa_entry_t *find_match_mach(struct list_head *head, saa_entry_t *entry)
{
    struct list_head *pos;
    list_for_each(pos, head) {
        saa_entry_t *match = list_entry(pos, saa_entry_t, list);
        if(strcmp(match->mach_code, entry->mach_code) == 0) {
            return match;
        }
    }
    return NULL;
}

saa_entry_t *find_match_auth(struct list_head *head, saa_entry_t *entry)
{
    struct list_head *pos;
    list_for_each(pos, head) {
        saa_entry_t *match = list_entry(pos, saa_entry_t, list);
        if(strcmp(match->auth_code, entry->auth_code) == 0) {
            return match;
        }
    }
    return NULL;
}

int deal_auth_req(saa_entry_t *entry, struct list_head *head_yes, struct list_head *head_no, saa_entry_t **match)
{
    /* head_yes:  */
    *match = find_match_mach(head_yes, entry);
    if(*match) {
        //copy_entry(*match, entry);
        (*match)->online_tstamp = entry->online_tstamp;
        return CMD_RSP_AUTHED;
    }
    *match = find_match_mach(head_no, entry);
    if(*match) {
        //update_ip_mac_tstamp(*match, entry);
        (*match)->online_tstamp = entry->online_tstamp;
        return CMD_RSP_UNAUTH;
    }
    *match = (saa_entry_t *)calloc(1, sizeof(saa_entry_t));
    if(NULL == *match) {
        return ERR_NO_MEM;
    }
    //copy_entry(*match, entry);
    (*match)->online_tstamp = entry->online_tstamp;
    list_add_tail(&((*match)->list), head_no);
    return CMD_RSP_UNAUTH;
}

int deal_access_req(saa_entry_t *entry, struct list_head *head_yes, struct list_head *head_no, saa_entry_t **match)
{
    /* look up in head_yes */
    *match = find_match_auth(head_yes, entry);
    if(*match) {
        (*match)->online_tstamp = entry->online_tstamp;
        return CMD_RSP_ACCESS_SUCCESS;
    }
    return CMD_RSP_ACCESS_FAILURE;
}


int deal_exit_req(saa_entry_t *entry, struct list_head *head_yes, struct list_head *head_no, saa_entry_t **match)
{
    *match = find_match_auth(head_yes, entry);
    if(*match) {
        //copy_entry(*match, entry);
        (*match)->online_tstamp = 0;
        return CMD_RSP_EXIST;
    }
    return CMD_RSP_EXIST;
}


