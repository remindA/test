/*
 * =====================================================================================
 *
 *       Filename:  pmonitor.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年07月20日 14时39分57秒
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
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>
#include <sys/time.h>
#include <ctype.h>
#include <sys/select.h>
#include <syslog.h>
#include "utils_net.h"
#include "mylist.h"

#define LEN_PROG 128
#define LEN_LOG  128
#define LEN_BACKLOG 10

#define ACTION_UNKNOW  0
#define ACTION_SHOW    1
#define ACTION_START   2
#define ACTION_STOP    3
#define ACTION_RESTART 4

typedef struct child_info {
    int argc;
    char **argv;
    pid_t pid;
    int death_cnt;
    char obituary[LEN_LOG];
    struct list_head list;
}child_info_t;


struct list_head head_child;
char *config_file = NULL;
const char *local_ip = "127.0.0.1";
unsigned short local_port = 50000;

void Usage(const char *prog);
int _main_command(int argc, char **argv);
int _main_monitor();
void process_zombie(struct list_head *head);
void process_reboot(struct list_head *head);
void process_death(struct list_head *head);
void process_command(struct list_head *head, int fd);
child_info_t *find_match_child(struct list_head *head, child_info_t *child);
int child_has_same_args(child_info_t *e1,child_info_t *e2);
int parse_arguments(child_info_t *entry, const char *buff);
void free_argv(char **argv);
void process_command_show(int fd, struct list_head *head);
void child_info_free(child_info_t *child);
int str_not_number(const char *str);
void argv_to_str(char **argv, char *str);

void Usage(const char *prog)
{
    printf("Usage:\n");
    printf("\t %s", prog);
    printf("\t %s show \n", prog);
    printf("\t %s start   command arguments\n", prog);
    printf("\t %s stop    command arguments \n", prog);
    printf("\t %s restart command arguments\n", prog);
    printf("\t %s stop    -p pid \n", prog);
    printf("\t %s restart -p pid \n", prog);
}

int main(int argc, char **argv)
{
    return argc==1?_main_monitor():_main_command(argc, argv);
}

int _main_command(int argc, char **argv)
{
    if(strcmp(argv[1], "start") != 0 &&
            strcmp(argv[1], "stop") != 0 &&
            strcmp(argv[1], "restart") != 0 &&
            strcmp(argv[1], "show") != 0) {
        Usage(argv[0]);
        return 0;
    }

    int fd = sock_connect_timeout(local_ip, local_port, 3);
    if(fd < 0) {
        return 0;
    }

    int i;
    char buff[1024] = {0};
    for(i = 1; i < argc-1; i++) {
        strcat(buff, argv[i]);    
        strcat(buff, " ");
    }
    strcat(buff, argv[argc-1]);
    write(fd, buff, strlen(buff));
    if(sock_set_nonblock(fd) < 0 || sock_set_reuseaddr(fd) < 0) {
        printf("Cannot sock_set_nonblock or sock_set_reuseaddr\n");
        close(fd);
        return 0;
    }
    
    fd_set rset;
    struct timeval tout;
    tout.tv_sec = 3;
    tout.tv_usec = 0;
    FD_ZERO(&rset);
    FD_SET(fd, &rset);
    switch(select(fd+1, &rset, NULL, NULL, &tout)) {
    case  -1:
        perror("select()");
        break;
    case 0:
        printf("No Response in %ld seconds\n", tout.tv_sec);
    default:
        while(( i = read(fd, buff, sizeof(buff) > 0))) {
            printf("%.*s", i, buff); 
        }
        printf("\n");
    }
    close(fd);
    return 0;
}

int str_not_number(const char *str)
{
    char *c;
    for(c = str; *c != '\0'; c++) {
        if(!isdigit(*c)) {
            return 1;
        }
    }
    return 0;
}

int _main_monitor()
{
    switch(fork()) {
    case 0:
        break;
    case -1:
        perror("pmonitor: cannot be deamon process. fork()");
        syslog(LOG_INFO, "pmonitor: Cannot be deamon process, fork()");
        return -1;
    default:
        return 0;
    }
    char log_tag[128] = {0};
    sprintf(log_tag, "pmonitor[%d]", getpid());
    openlog(log_tag, LOG_CONS, LOG_USER);
    int ret;
    init_list_head(&head_child);
#if 0
    if(read_child_config(&head_child, config_file) < 0) {
        printf("pmonitor: cannot read_child_config()\n");
        return 0;
    }
#endif

    int s_fd = sock_create_tcp(local_ip, local_port, LEN_BACKLOG);
    if(s_fd < 0) {
        printf("pmonitor: cannot sock_create_tcp()\n");
        syslog(LOG_INFO, "pmonitor: Cannot sock_create_tcp()");
        return 0;
    }
    if(sock_set_nonblock(s_fd) < 0) {
        printf("pmonitor: cannot sock_set_nonblock()\n");
        syslog(LOG_INFO, "pmonitor: Cannot sock_set_nonblock()");
        return 0;
    }
    //init child process
    struct list_head *pos;
    list_for_each(pos, &head_child) {
        child_info_t *entry = list_entry(pos, child_info_t, list);
        entry->pid = fork();
        switch(entry->pid) {
        case -1:
            perror("fork()");
            break;
        case 0:
            close(STDIN_FILENO);
            close(STDOUT_FILENO);
            close(STDERR_FILENO);
            execvp(entry->argv[0], entry->argv);
            exit(0);
        default:
            break;
        }
    }

    int c_fd[LEN_BACKLOG] = {0};
    int fd_max;
    fd_set rset;
    struct timeval timeout;
    unsigned int tout_cnt = 0;

    //main_loop
    int i;
    while(1) {
        fd_max = 0;
        timeout.tv_sec = 3;
        timeout.tv_usec = 0;
        FD_ZERO(&rset);
        FD_SET(s_fd, &rset);
        fd_max = fd_max<s_fd?s_fd:fd_max;
        for(i = 0; i < LEN_BACKLOG; i++) {
            if(c_fd[i] > 0) {
                FD_SET(c_fd[i], &rset);
                fd_max = fd_max<c_fd[i]?c_fd[i]:fd_max;
            }
        }
        ret = select(fd_max+1, &rset, NULL, NULL, &timeout);
        if(ret < 0) {
            perror("select()");
            if(errno == EINTR) {
                continue;
            }
        }
        else if(0 == ret) {
            //printf("select timeout\n");
            tout_cnt++;
            if(tout_cnt%2 == 0) {
                process_zombie(&head_child);
            }
        }
        else {
            //printf("select active\n");
            if(FD_ISSET(s_fd, &rset)) {
                struct sockaddr_in addr;
                socklen_t socklen = sizeof(addr);
                int fd = accept(s_fd, (struct sockaddr *)(&addr), &socklen);
                if(fd < 0) {
                    perror("accept()");
                }
                else {
                    for(i = 0; i < LEN_BACKLOG; i++) {
                        if(c_fd[i] <= 0) {
                            c_fd[i] = fd;
                            break;
                        }
                    }
                }
            }
            for(i = 0; i < LEN_BACKLOG; i++) {
                if(c_fd[i] > 0 && FD_ISSET(c_fd[i], &rset)) {
                    process_command(&head_child, c_fd[i]);
                    close(c_fd[i]);
                    c_fd[i] = -1;
                }
            }
        }

        process_death(&head_child);

        process_reboot(&head_child);
    }
    return 0;    
}

void process_zombie(struct list_head *head)
{
    return;
}

void process_reboot(struct list_head *head)
{
    struct list_head *pos;
    list_for_each(pos, head) {
        child_info_t *entry = list_entry(pos, child_info_t, list);
        if(entry->pid <= 0) {
            entry->pid = fork();
            switch(entry->pid) {
            case -1:
                perror("fork()");
                break;
            case 0:
                close(STDIN_FILENO);
                close(STDOUT_FILENO);
                close(STDERR_FILENO);
                execvp(entry->argv[0], entry->argv);
                exit(0);
            default:
                {
                char argv_str[1024] = {0}; 
                argv_to_str(entry->argv, argv_str);
                syslog(LOG_INFO, "start/restart pid=%d, %s", entry->pid, argv_str);
                break;
                }
            }
        }
    }
}


void process_command(struct list_head *head, int fd)
{
    int ret;
    char buff[512] = {0};
    ret = read(fd, buff, sizeof(buff));
    if(ret < 0) {
        perror("read()");
        return;
    }
    else if(ret == 0) {
        printf("client off\n");
        return;
    }

    printf("process_command: read = [%s]\n", buff);

    char action[64] = {0};
    char prog[64] ={0};
    char rsp[128] = {0};
    ret = sscanf(buff, "%s %s", action, prog);

    if(ret == 1 && strcmp(action, "show") == 0) {
        ret = ACTION_SHOW;
        goto done;
    }
    else if(ret != 2) {
        printf("process_command: ret ！= 2\n");
        return;
    }

    child_info_t child;
    memset(&child, 0, sizeof(child));
    parse_arguments(&child, buff);

    child_info_t *match = find_match_child(head, &child);
    child_info_free(&child);

    /* both start support arguments */
    if(strcmp(action, "start") == 0) {
        printf("start means add entry\n");
        ret = ACTION_START;
        if(match) {
            goto err;
        }
        child_info_t *entry = (child_info_t *)calloc(1, sizeof(child_info_t));
        if(NULL== entry) {
            perror("calloc()");
            goto err;
        }
        if(parse_arguments(entry, buff) < 0) {
            free(entry);
            printf("parse_arguments: error");
            goto err;
        }
        char argv_str[1024] = {0}; 
        argv_to_str(entry->argv, argv_str);
        syslog(LOG_INFO, "pmonitor start %s", argv_str);
        list_add_tail(&(entry->list), head);
    }
    else if(strcmp(action, "stop") == 0) {
        printf("stop mean del entry\n");
        ret == ACTION_STOP;
        if(!match) {
            goto err;
        }
        if(match->pid > 0) {
            list_del(&(match->list));
            kill(match->pid, SIGKILL);
            char argv_str[1024] = {0}; 
            argv_to_str(match->argv, argv_str);
            syslog(LOG_INFO, "pmonitor stop pid=%d, %s", match->pid, argv_str);
            child_info_free(match);
            free(match);
        }
    }
    else if(strcmp(action, "restart") == 0) {
        /* if you want to restart with changing argments, you need to stop and then start */
        printf("resart means terminate\n");
        ret = ACTION_RESTART;
        if(!match || match->pid < 0) {
            goto err;
        }
        kill(match->pid, SIGKILL);
        char argv_str[1024] = {0}; 
        argv_to_str(match->argv, argv_str);
        syslog(LOG_INFO, "pmonitor stop pid=%d, %s", match->pid, argv_str);
        match->pid = -1;
    }
    else if(strcmp(action, "show") == 0) {
        ret == ACTION_SHOW;
    }
    else {
        ret = ACTION_UNKNOW;
        goto err;
    }
done:
    switch(ret) {
    case ACTION_START:
    case ACTION_STOP:
    case ACTION_RESTART:
        sprintf(rsp, "OK: %s", buff);
        write(fd, rsp, strlen(rsp));
        break;
    case ACTION_SHOW:
        process_command_show(fd, head);
    }
    printf("parse_command is ok\n");
    return;

err:
    switch(ret) {
    case ACTION_START:
    case ACTION_STOP:
    case ACTION_RESTART:
        sprintf(rsp, "NOT OK: %s", buff);
        write(fd, rsp, strlen(rsp));
    }
    printf("parse_command is failed\n");
}

child_info_t *find_match_child(struct list_head *head, child_info_t *child)
{
    /* compare argc, argv */
    struct list_head *pos;
    list_for_each(pos, head) {
        child_info_t *entry = list_entry(pos, child_info_t, list);
        if(child_has_same_args(entry, child)) {
            return entry;
        }
    }
    return NULL;
}

int child_has_same_args(child_info_t *e1,child_info_t *e2)
{
    int same_argc = 0;
    int same_argv = 1;
    if(e1->argc == e2->argc) {
        same_argc = 1;
    }
    else {
        return 0;
    }
    int i;
    for(i = 0; i < e1->argc; i++) {
        if(e1->argv[i] && e2->argv[i] && strcmp(e1->argv[i], e2->argv[i])) {
            same_argv = 0;
            break;
        }
    }
    return same_argc&&same_argv?1:0;
}


void argv_to_str(char **argv, char *str)
{
    char **tmp;
    for(tmp = argv; *tmp; tmp++) {
        strcat(str, *tmp);
    }
}


void free_argv(char **argv)
{
    char **tmp;
    for(tmp = argv; *tmp; tmp++) {
        printf("free arguments: %s\n", *tmp);
        free(*tmp);
        *tmp = NULL;
    }
}

void process_command_show(int fd, struct list_head *head)
{
    const char *prefix = "pmonitor show\n";
    write(fd, prefix, strlen(prefix));
    struct list_head *pos;
    list_for_each(pos, head) {
        child_info_t *entry = list_entry(pos, child_info_t, list);
        if(entry->pid > 0) {
            char info[1024] = {0};
            sprintf(info, "%d\t", entry->pid);
            char **tmp;
            for(tmp = entry->argv; *tmp; tmp++) {
                strcat(info, *tmp);
                strcat(info, " ");
            }
            strcat(info, "\n");
            write(fd, info, strlen(info));
        }
    }
}

void process_death(struct list_head *head)
{
    int status;
    pid_t pid;
    struct list_head *pos; 
    while((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {
        list_for_each(pos, head) {
            child_info_t *entry = list_entry(pos, child_info_t, list);
            if(pid == entry->pid) {
                printf("child %d, %s exited and cycled\n", entry->pid, entry->argv[0]);
                char argv_str[1024] = {0}; 
                argv_to_str(entry->argv, argv_str);
                if(WIFEXITED(status)) {
                    syslog(LOG_INFO, "%d, %s, die normally", entry->pid, argv_str);
                    sprintf(entry->obituary, "%d, die normally", entry->pid);
                }
                if(WIFSIGNALED(status)) {
                    syslog(LOG_INFO, "%d, %s, die beacuse of signal %d", entry->pid, argv_str, WTERMSIG(status));
                    sprintf(entry->obituary, "%d, die because of signal %d", entry->pid, WTERMSIG(status));
                }
                entry->pid = -1;
                break;
            }
        }
    }
}

void child_info_free(child_info_t *child)
{
    free_argv(child->argv);
    free(child->argv);
    child->argv = NULL;
}

int parse_arguments(child_info_t *entry, const char *buff)
{
    //how to know arguments is wrong and process faild to start

    /* start  http_worker  10.10.10.231  5060  192.168.1.10  5060 */

    entry->argc = 0;
    entry->argv = NULL;
    char *c;
    char *start = NULL;
    char *end = NULL;
    for(c = strchr(buff, ' '); *c != '\0'; c++) {
        if(isspace(*c) && (*(c+1) != '\0' && !isspace(*(c+1)))) {
            start = c+1;
            printf("start = [%s]\n", start);
        }
        if(!isspace(*c) && (*(c+1) == '\0' || (*(c+1) != '\0' && isspace(*(c+1))))){
            end = c;
            printf("end = [%s]\n", end);
        }
        if(start && end && end > start) {
            entry->argc++;
            printf("entry->argc = %d\n", entry->argc);
            char **tmp = (char **)realloc(entry->argv, (entry->argc+1)*sizeof(char *));
            if(NULL == tmp) {
                perror("realloc");
                child_info_free(entry);
                return -1;
            }
            entry->argv = tmp;
            entry->argv[entry->argc] = NULL;
            entry->argv[entry->argc-1] = (char *)calloc(1, 1+end-start+1);
            if(NULL == entry->argv[entry->argc-1]) {
                perror("calloc()");
                child_info_free(entry);
                return -1;
            }
            strncpy(entry->argv[entry->argc-1], start, 1+end-start);
            int i;
            for(i = 0; i <= entry->argc; i++) {
                printf("%d --> %s\n", i, entry->argv[i]);
            }
            start = end = NULL;
        }
    }
    printf("parse_arguments: ok\n");
    return 0;
}


