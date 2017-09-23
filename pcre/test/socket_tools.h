#ifndef _SOCKETTOOLS_
#define _SOCKETTOOLS_
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define SCFG_CLIENT
#define CGI
/* path of socket log */
#ifndef SOCKET_LOG
#define SOCKET_LOG  "log"
#endif
#include "socket_header.h"
extern char *nvram_data;
int socket_connect();
/*
 * Read data from socket
 * @param	header	like packet's header
 * @param	data	save data in here
 * @param	infd	write data to here
 * @return	0 success -1 error
 */
int socket_read(scfgmgr_header **header,char **data,int infd);

/*
 * Write data to socket
 * @param	header	like packet's header
 * @param	data	data that you want write to socket
 * @param	infd	read data from here
 * @return	0 success -1 error
 */
int socket_write(scfgmgr_header *header,char *data,int infd);

#ifdef TEST
/*
 * Save log
 * @param	msg	message 
 * @param	len	message length
 */
void socket_log(char *msg,int len);
#endif

/*
 *  The fllowing funtions are designed for socket client AP , ex: CGI  
 */
#ifdef SCFG_CLIENT
/*
 * Communication with scfgmgr   
 * @param	shd	header for write 
 * @param	sdata	data for write
 * @param	rhd	header for read   
 * @param	rdata	data for read
 * @return	0 success -1 error
 */
int scfgmgr_connect(scfgmgr_header *shd,char *sdata,scfgmgr_header **rhd,char **rdata);

/*
 * Send command to scfgmgr
 * @param       cmd   command  
 * @return      0 success -1 error
 */
int scfgmgr_cmd(int cmd,char **rdata);
#define scfgmgr_commit() {char *tmp;scfgmgr_cmd(SCFG_COMMIT,&tmp);}
/*
 * Get all configuration data from scfgmgr
 * @param       rdata   save data in this point
 * @return      0 success -1 error
 */
int scfgmgr_getall(char **rdata);	


int scfgmgr_get(char *data,char **rdata);	

/*
 * Save configuration data to scfgmgr
 * @param       data     data ,you want save
 * @param       value    value
 * @return      0 success -1 error
 */
extern int scfgmgr_set(char *name,char *value);

int scfgmgr_sendfile(char *data,int len);
int scfgmgr_console(char *data,char **rdata);
/*
 * Parse value form data
 * @param       name     parse this name's value
 * @return      value 
 */
extern char* value_parser(char *name);
#endif

#endif
