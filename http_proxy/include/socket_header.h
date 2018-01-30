/* ScMM */
#define SCM_MAGIC 0x53634d4d

#define DEFAULT_REMOTE_IP   "192.168.0.1"
#define DEFAULT_REMOTE_PORT 32764 
//#define DEFAULT_REMOTE_PORT 12345 

/* header struct*/
typedef struct scfgmgr_header_s{
	unsigned long   magic;
	//unsigned long	cmd;
	int		cmd;
	unsigned long	len;
} scfgmgr_header;

enum {
	SCFG_WARNING=-2,
	SCFG_ERR,
	SCFG_OK,
	SCFG_GETALL,
	SCFG_GET,
	SCFG_SET,
	SCFG_COMMIT,
	SCFG_TEST,
	SCFG_ADSL_STATUS,
	SCFG_CONSOLE,
	SCFG_RECEIVE,
	SCFG_VERSION,
	SCFG_LOCAL_IP,
	SCFG_RESTORE,
	SCFG_CHECKSUM,
	SCFG_CFG_INIT,
	SCFG_SUPERG,
}cmd_type;
