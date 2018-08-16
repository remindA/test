/*
 * =====================================================================================
 *
 *       Filename:  config_sr04i.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年07月27日 17时30分44秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#include "config.h"

int read_config_yes(const char *config, struct list_head *head)
{
	int ret = scfgmgr_getall(&nvram_data);
	if(ret < 0 || NULL == nvram_data)
		return -1;
    char auth_table[MAX_BUFF] = {0};
    char *pval = value_parser(config);
    printf("%s=%s\n", config, pval);
    strcpy(auth_table, pval);
    SAFE_FREE(nvram_data);
    int cnt = 0;
    int i = 0;
    char *str, *token, *saveptr;
    for(i = 1, str = auth_table; ; i++, str = NULL)
    {
        token = strtok_r(str, ";", &saveptr);
        if(token == NULL) {
            return 0;
        }
        printf("yes_entry_%d=%s\n", i, token);
        saa_entry_t entry;
        if(parse_entry(token, entry) < 0) {

        }
        if(add_entry(head, &entry) < 0) {

        }
        cnt++;
    }
    return cnt;
}

/*
 * 格式和nvram中一模一样,没有换行符
 */
int read_config_no(const char *filepath, struct list_head *head)
{
    int fd = open(filepath, O_RDWR);
	if(fd < 0) {
		perror("open()");
		return -1;
	}
    /*　文件锁 */
    struct flock lock;
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;
    if(fcntl(fd, F_SETLKW, &lock) != 0)
    {
        close(fd);
        perror("fcntl()-get_auth_table_from_file");
        return -1;
    }
    char auth_table[MAX_BUFF] = {0};
    read(fd, auth_table, sizeof(auth_table));
    lock.l_type = F_UNLCK;
    fcntl(fd, F_SETLKW, &lock);
	close(fd);
    int i = 0;
	int cnt = 0;
	s_element ele;
    char *str, *token, *saveptr;
    for(i = 1, str = auth_table; ; i++, str = NULL)
    {
        token = strtok_r(str, ";", &saveptr);
        if(token == NULL) {
            return 0;
        }
        printf("no_entry_%d=%s\n", i, token);
        saa_entry_t *entry = (saa_entry_t *)calloc(1, sizeof(saa_entry_t));
        if(NULL == entry) {

        }
        if(parse_entry(token, entry) < 0) {

        }
        list_add_tail(&(entry->list), head);
        cnt++;
    }
	return cnt;
}


int parse_entry(const char *line, saa_entry_t *entry)
{
	if(NULL == line)
		return -1;
	//auth_state#ip#mac#cpu#disk#host_name#machine_code#
	//增删s_client_info结构体和saa_element结构体时这里要修改
	char *format = "%[^#]#%[^#]#%[^#]#%[^#]#%[^#]#%[^#]#%[^#]#"; 
	int ret = 0; 
	//增删s_client_info结构体和saa_element结构体时这里要修改
	ret = sscanf(line, format, entry->auth_state
                             , entry->ip
                             , entry->mac
                             , entry->mach_code
                             , entry->auth_code
                             , entry->mark);
#if DEBUG
	if(ret >= 0)
		printf("parse_line sscanf ret = %d\n", ret);
#endif
	return ret;
}


void update_unauth_file(struct list_head *head_no,  const char *config_file_no)
{
    /* update unauth config file */ 
    int fd = open(config_file_no, O_CREAT | O_RDWR | O_TRUNC, 0666);
    if(fd < 0) {
        perror("open()");
        return -1;
    }
    struct flock lock;
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;
    if(fcntl(fd, F_SETLKW, &lock) != 0) {
        close(fd);
        perror("fcntl()-update_auth_table_to_file");
        return -1;
    }
	//auth_state#ip#mac#cpu#disk#host_name#machine_code#
    list_for_each(pos, head_no) {
        char buff[LEN_ENTRY_STR] = {0};
		int ret = 
        sprintf(buff, format,  entry->auth_state
                             , entry->ip
                             , entry->mac
                             , entry->mach_code
                             , entry->auth_code
                             , entry->mark);
		if(ret < 0) {
			printf("update node_%d to file failed\n", num);
        }
		if(ret < 7) {
			printf("update node_%d to file incomplete\n", num);
        }
        write(fd, buff, strlen(buff));
	}
    lock.l_type = F_UNLCK;
    fcntl(fd, F_SETLKW, &lock);
    close(fd);
	return 0;
}


