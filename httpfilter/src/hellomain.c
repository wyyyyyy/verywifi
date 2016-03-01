/*
 * httpfilter.c - definitions for the hecuba framebuffer driver
 *
 * Copyright (C) 2013 by wuyao
 *
 *
 */


#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/skbuff.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/sched.h>
#include <linux/moduleparam.h>
#include "pcreposix.h"
#include "pcre.h"
#include "pcre_internal.h"
#include <linux/workqueue.h>
#include <linux/inet.h> /*in_aton()*/
#include <net/ip.h>
#include <net/tcp.h>
#include "hellomain.h"

#include <crypto/hash.h>
#include <linux/scatterlist.h>
#include <linux/gfp.h>
#include <linux/err.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/highmem.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_helper.h>
//#include <net/netfilter/nf_nat_rule.h>

#include <linux/zlib.h>

static struct nf_hook_ops 	HF_ops;
static struct timer_list 		HF_tmlist_file;
static struct timer_list 		HF_tmlist_rule;
static struct HFRuleCtl 		*pstHFLinkCtl;
static struct HFRulUpdCtl 	*pstHFRulUpdCtl;
static struct work_struct 		HF_filework;
static struct work_struct 		HF_rulework;
static struct blkcipher_desc 	desc;
static int 				 		timer_flag1, timer_flag2;

#ifdef VER_REL
#define DEBUG(format,...)
#else
#define DEBUG(format,...) printk(KERN_DEBUG format, ##__VA_ARGS__)
#endif

#ifdef VER_REL
#define INFO(format,...)
#else
#define INFO(format,...) printk(KERN_INFO format, ##__VA_ARGS__)
#endif

#ifdef VER_REL
#define WARNING(format, ...)
#else
#define WARNING(format,...) printk(KERN_WARNING format, ##__VA_ARGS__)
#endif


#define nf_nat_mangle_tcp_packet(arg1,arg2,arg3,arg4,arg5,arg6,arg7) nf_nat_mangle_tcp_packet_hf(arg1,arg2,arg3,arg4,arg5,arg6,arg7)

//---------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------
#define				HF_OK					0
#define				HF_ERROR				1
#define				HF_SKIP					3
#define				HF_CANT_PROC			2
#define				NF_OK					1
#define				NF_ERR					0
#define				HF_TLV_ERROR			2
#define				HF_MISS_H1				3
#define				HF_MISS_T2				4

#define				HF_TLVTYPE_REGEXP		9
#define				HF_TLVTYPE_ALIETIME		4
#define				HF_TLVTYPE_SERCHH1		10	//str:----H1---H2----T2---T1-----
#define				HF_TLVTYPE_SERCHT2		11
#define				HF_TLVTYPE_REPLACE1		12	//replace  H2----T2
#define				HF_TLVTYPE_REPLACE2		13	//replace  H1---H2----T2---T1
#define				HF_TLVTYPE_FORRESPOND	0x0100
#define				HF_TLVTYPE_REDIRECT		0x010E
#define				HF_TLVTYPE_FINISH		255
#define				HF_TLV_REGFULL			256
#define				HF_TLVTYPE_SERCHH1_B	0x010a
#define				HF_TLVTYPE_SERCHT2_B    	0x010b
#define				HF_TLVTYPE_REPLACE1_B	0x010c
#define				HF_TLVTYPE_REPLACE2_B	0x010d
#define				HF_TLVTYPE_VERFLAG		20
#define				HF_TLVTYPE_APPFLAG		21
#define				HF_TLVTYPE_CANCLETLV	0x010F
#define				HF_TLVTYPE_MISREQ		0x0110
#define				HF_TLVTYPE_MISTIME    	         0x0111
#define				HF_L1TLVTYPE_MISREQPROC	3

#define 			         HF_SET_RULENO(statusold, statusnew)    ((statusold) = (((long)(statusnew))<<24)|(statusold & (~(((long)(0x000000FF))<<24))))
#define                               ASSERT(x)       { if(NULL == x) return HF_ERROR; }
#define				HF_FROM_LAN			0
#define				HF_FROM_WAN			1
#define				HF_TLV_MAXLEN			2048
#define 			         HF_HTTPFLD_CENTLEN 		16
#define				HF_HTTP_CHUNKED		1
#define				HF_HTTP_UNCHUNKED		0
#define				HF_HTTP_UKNOW			2
#define				HF_HTP_HEAD				0
#define				HF_HTP_BODY				1
#define				HF_HTP_TAIL				2
#define				HF_HTP_MIDEND			3
#define				HF_IP_FREGMENT			1
#define				HF_TMS_INIT				0
#define				HF_TMS_H				1
#define				HF_TMS_T				2
#define				HF_TMS_R				3
#define				HF_SEQ_RCODNUM		5
#define				HF_TLV_EFFECTIVE		         1
#define				HF_TLV_INEFFECTIVE		0
#define				HF_HTPPAK_NUM			64
#define				HF_RUL_40X 				40

enum 	HF_L1TLVTYPE{
		HF_L1TLVTYPE_WHITE = 0,
		HF_L1TLVTYPE_REDIRECT,
		HF_L1TLVTYPE_MODIFY,
		HF_L1TLVTYPE_MISREQPROC_REDI,
		HF_L1TLVTYPE_UPDATE,
		HF_L1TLVTYPE_MISREQPROC_MODIFY
};


struct http_para{
unsigned char *hdr;
unsigned int hdlen;
unsigned int cntSPos;
unsigned int cntEPos;
unsigned int chkSPos;
unsigned int chkEPos;
int len;
unsigned int uiPakNo;
unsigned int htmSPos;
unsigned int chkHeadNum;
};

struct hfHttpPakCtl{
	int isChunked;			//是否分组传输
	int exptRcvLen;
	int acuRcvLen;
	int exptSndLen;
	int acuSndLen;
	unsigned char *pRule;
	unsigned int uiRulNo;			//对应的规则编号
	unsigned int uiRulType;
	unsigned int sPort;
	unsigned char sIp4;
	unsigned char reserved[3];
};

struct hFStrMachine{
	struct sk_buff *skb;
	unsigned int h1;
	unsigned int h2;
	unsigned int t2;
	unsigned int t1;
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	unsigned int direction;
	struct http_para	http;
	unsigned char *tcphdr;
	unsigned int tcpHdLen;
	unsigned int ipHdLen;
	unsigned int nxtHtpCtlNo;
	unsigned int tmStatus;
	unsigned int PrcOnBk;
	int lendiff;
};

struct hFStrMachine *pHFStrMachine;
struct hfHttpPakCtl hfHtpPakCtl[HF_HTPPAK_NUM];
unsigned char hfSpace[512] = "                                                                                                                                                                                                                         ";

static unsigned long interval  = 0;
/****************************************************************************************************************/
static void mangle_contents(struct sk_buff *skb,
			    unsigned int dataoff,
			    unsigned int match_offset,
			    unsigned int match_len,
			    const char *rep_buffer,
			    unsigned int rep_len)
{
	unsigned char *data;

	BUG_ON(skb_is_nonlinear(skb));
	data = skb_network_header(skb) + dataoff;

	/* move post-replacement */
	memmove(data + match_offset + rep_len,
		data + match_offset + match_len,
		skb->tail - (skb->network_header + dataoff +
			     match_offset + match_len));

	/* insert data from buffer */
	memcpy(data + match_offset, rep_buffer, rep_len);

	/* update skb info */
	if (rep_len > match_len) {
		pr_debug("nf_nat_mangle_packet: Extending packet by "
			 "%u from %u bytes\n", rep_len - match_len, skb->len);
		skb_put(skb, rep_len - match_len);
	} else {
		pr_debug("nf_nat_mangle_packet: Shrinking packet from "
			 "%u from %u bytes\n", match_len - rep_len, skb->len);
		__skb_trim(skb, skb->len + rep_len - match_len);
	}

	/* fix IP hdr checksum information */
	ip_hdr(skb)->tot_len = htons(skb->len);
	ip_send_check(ip_hdr(skb));
}

static int enlarge_skb(struct sk_buff *skb, unsigned int extra)
{
	if (skb->len + extra > 65535)
		return 0;

	if (pskb_expand_head(skb, 0, extra - skb_tailroom(skb), GFP_ATOMIC))
		return 0;

	return 1;
}

static void nf_nat_csum(struct sk_buff *skb, const struct iphdr *iph, void *data,
			int datalen, __sum16 *check, int oldlen)
{
	struct rtable *rt = skb_rtable(skb);

	if (skb->ip_summed != CHECKSUM_PARTIAL) {
		if (!(rt->rt_flags & RTCF_LOCAL) &&
		    (!skb->dev || skb->dev->features & NETIF_F_V4_CSUM)) {
			skb->ip_summed = CHECKSUM_PARTIAL;
			skb->csum_start = skb_headroom(skb) +
					  skb_network_offset(skb) +
					  iph->ihl * 4;
			skb->csum_offset = (void *)check - data;
			*check = ~csum_tcpudp_magic(iph->saddr, iph->daddr,
						    datalen, iph->protocol, 0);
		} else {
			*check = 0;
			*check = csum_tcpudp_magic(iph->saddr, iph->daddr,
						   datalen, iph->protocol,
						   csum_partial(data, datalen,
								0));
			if (iph->protocol == IPPROTO_UDP && !*check)
				*check = CSUM_MANGLED_0;
		}
	} else
		inet_proto_csum_replace2(check, skb,
					 htons(oldlen), htons(datalen), 1);
}

static int nf_nat_mangle_tcp_packet_hf(struct sk_buff *skb,
					   struct nf_conn *ct,
					   enum ip_conntrack_info ctinfo,
					   unsigned int match_offset,
					   unsigned int match_len,
					   const char *rep_buffer,
					   unsigned int rep_len)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	int oldlen, datalen;

	if (!skb_make_writable(skb, skb->len))
		return 0;

	if (rep_len > match_len &&
	    rep_len - match_len > skb_tailroom(skb) &&
	    !enlarge_skb(skb, rep_len - match_len))
		return 0;

	SKB_LINEAR_ASSERT(skb);

	iph = ip_hdr(skb);
	tcph = (void *)iph + iph->ihl*4;

	oldlen = skb->len - iph->ihl*4;
	mangle_contents(skb, iph->ihl*4 + tcph->doff*4,
			match_offset, match_len, rep_buffer, rep_len);
	/**************************************************/
	pHFStrMachine->lendiff += (rep_len-match_len);
	/**************************************************/

	datalen = skb->len - iph->ihl*4;
	nf_nat_csum(skb, iph, tcph, datalen, &tcph->check, oldlen);

	set_bit(IPS_SEQ_ADJUST_BIT, &ct->status);
	return 1;
}
/****************************************************************************************************************/

//---------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------
unsigned int  pow10(unsigned int num){
    unsigned int out = 1;
    while(num){
        out *= 10;
        num--;
    }
    return out;
}
void HF_atoi(unsigned char *s, unsigned int len, int* out){
    unsigned int len2 = len;
    while(len2){
        (*out) += ((int)(*(s+len-len2)-0x30))*pow10(len2-1);
        len2--;
    };
}
unsigned int  pow16(unsigned int num){
    unsigned int out = 1;
    while(num){
        out *= 16;
        num--;
    }
    return out;
}

void HF_atoi_hex(unsigned char *s, unsigned int len, int* out){
    unsigned int len2 = len;
	unsigned char tmp = 0;
		
		*out = 0;
    while(len2){
		tmp = (*(s+len-len2));
        (*out) += ((int)((tmp< 0x3B)?(tmp-0x30):(tmp-87)))*pow16(len2-1);
        len2--;
    };
}
//---------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------
static int HF_init_cbc(void)
{
    u8 key[HF_KEY_LEN] = "rule";
    static u8 hashkey[HF_KEY_LEN];
    struct crypto_blkcipher *tfm;
    
    tfm = crypto_alloc_blkcipher("cbc(aes)", 0, CRYPTO_ALG_ASYNC);
    if (IS_ERR(tfm)) {
		DEBUG("crypto_alloc_blkcipher failed");
		desc.tfm = ERR_PTR(-EINVAL);
		return 1;
	}
	desc.tfm = tfm;
	desc.flags = 0;

	HF_md5_generate(key, strlen(key), hashkey);
    crypto_blkcipher_setkey(tfm, hashkey, HF_KEY_LEN);
    
	return 0;
}

static int HF_md5_generate(unsigned char* src, int srclen, unsigned char* hash)
{
	int 					sdescsize, iRetCode;
	struct shash_desc 		*sdescmd5;
	struct crypto_shash 	*tfmmd5;
	
	tfmmd5 = crypto_alloc_shash("md5", 0, 0);
	if(IS_ERR(tfmmd5))
	{
		DEBUG("Failed to alloc transform\n");
		return -1;
	}

	sdescsize = sizeof(struct shash_desc) + crypto_shash_descsize(tfmmd5);
	sdescmd5 = kmalloc(sdescsize, GFP_KERNEL);
	if(IS_ERR(sdescmd5))
	{
		DEBUG("Failed to alloc memory\n");
		iRetCode = -1;
		goto MALLOC_ERR;
	}

	sdescmd5->tfm = tfmmd5;
	sdescmd5->flags = 0x0;

	iRetCode = crypto_shash_init(sdescmd5);
	if(iRetCode)
	{
		iRetCode = -1;
		goto TFM_ERR;
	}

	crypto_shash_update(sdescmd5, src, srclen);
	iRetCode = crypto_shash_final(sdescmd5, hash);

	TFM_ERR:
		kfree(sdescmd5);
	MALLOC_ERR:
		crypto_free_shash(tfmmd5);

	return iRetCode;
}

static int HF_cypher_decrypt(char *str, size_t str_len)
{
    struct scatterlist sg;

    if (IS_ERR(desc.tfm)) {
        HF_init_cbc();
		return 1;
	}
    
	sg_init_one(&sg, str, str_len);
	crypto_blkcipher_decrypt(&desc, &sg, &sg, str_len);

	return 0;
}

void HF_file_copy()
{
	int result;
    char  cmdPath[]="/bin/cp";
	char* cmdArgv[]={cmdPath,HF_RULE_FILE_SRC,HF_RULE_FILE_DST, NULL};
    char* cmdEnvp[]={"HOME=/","PATH=/sbin:/bin:/usr/bin",NULL};
    result=call_usermodehelper(cmdPath,cmdArgv,cmdEnvp,1);	
}

void HF_file_rm()
{
	int result;
    char  cmdPath[]="/bin/rm";
	char* cmdArgv[]={cmdPath,"-rf",HF_RULE_FILE_SRC, NULL};
    char* cmdEnvp[]={"HOME=/","PATH=/sbin:/bin:/usr/bin",NULL};
    result=call_usermodehelper(cmdPath,cmdArgv,cmdEnvp,1);	
}

int HF_md5_check(unsigned char *src,int len, char *dst)
{
	int result = 0;
	unsigned char calMD5[16];

	src[len] = '\0';
	result = HF_md5_generate( src, len, calMD5);
	
	return memcmp(calMD5, dst, 16);
}

int HF_file_read_L1(char *filepath,unsigned char *buffer, int bufmaxlen, unsigned int *reallen){
	struct file 	*pMyFile = NULL;
	unsigned int	ltFileLen=0;
	mm_segment_t 	fs;
	int 			result;
	loff_t   		ltPos = 0;
	
	pMyFile = filp_open(filepath, O_RDWR, 0);
	if(IS_ERR(pMyFile))
	{
		DEBUG("Failed to open file\n");
		return HF_ERROR;
	}
	
	ltFileLen = pMyFile->f_dentry->d_inode->i_size;	
	if(ltFileLen>=bufmaxlen)
	{
		DEBUG("File format illegal\n");
		filp_close(pMyFile, NULL);
		return HF_ERROR;
	}

	fs = get_fs(); 
    set_fs(KERNEL_DS); 
	result 	= vfs_read(pMyFile, buffer, ltFileLen, &ltPos);
	set_fs(fs);
	filp_close(pMyFile, NULL);

	*reallen = ltFileLen;
	return HF_OK;
}

int HF_file_read(char *filepath,unsigned char **buffer, int bufmaxlen, unsigned int *reallen)
{
	struct file 	*pMyFile = NULL;
	unsigned int	ltFileLen=0;
	mm_segment_t 	fs;
	int 			result;
	loff_t   		ltPos = 0;
	
	pMyFile = filp_open(filepath, O_RDWR, 0);
	if(IS_ERR(pMyFile))
	{
		DEBUG("Failed to open file\n");
		return HF_ERROR;
	}
	
	ltFileLen = pMyFile->f_dentry->d_inode->i_size;	
	if(ltFileLen>=bufmaxlen)
	{
		DEBUG("File format illegal\n");
		filp_close(pMyFile, NULL);
		return HF_ERROR;
	}
	if(NULL == (*buffer))
		(*buffer) = kmalloc(ltFileLen+10, GFP_KERNEL);

	fs = get_fs(); 
    set_fs(KERNEL_DS); 
	result 	= vfs_read(pMyFile, *buffer, ltFileLen, &ltPos);
	set_fs(fs);
	filp_close(pMyFile, NULL);

	*reallen = ltFileLen;
	return HF_OK;
}
unsigned int HF_hexDump(unsigned char *src, int len, unsigned char *dst){
	int icount;

	ASSERT(src);
	ASSERT(dst);
	
	for(icount=0;icount<len;icount++){
		sprintf(dst+icount*2, "%02x", *(src+icount));
	}
	*(dst+len*2) = 0;
	return HF_OK;
}
unsigned int HF_fileDown(char *fileurl){
	unsigned char fDtmp[HF_RULE_SVR_URL_MAX_LEN+20+HF_MD5_LEN*2+HF_VERSION_MAXSIZE+HF_MACADDR_LEN*2+HF_RANDNUM_SIZE*2+HF_RULELIST_SIZE*2+16+HF_VENDORID_MAXSIZE*2];
	unsigned int  statSize = pstHFLinkCtl->aRuleGroupSize[pstHFLinkCtl->iCurListNo];
	unsigned int  statSize1 = pstHFLinkCtl->MisRCtlSize[pstHFLinkCtl->iCurListNo];
	unsigned int  fileurlLen = strlen(fileurl);
	unsigned int  curCor = 0, result;
	char  cmdPath[]="/usr/bin/aria2c";
	char* cmdArgv[]={cmdPath,"--connect-time=1","--timeout=1", "-d /tmp", "-o 1", "--allow-overwrite=true", fDtmp, NULL};
    char* cmdEnvp[]={"HOME=/","PATH=/sbin:/bin:/usr/bin",NULL};
	/*准备文件下载参数MD5,RANDNUM,MAC ADDR,STATICTICS,VERSION*/
	ASSERT(fileurl);

	/*构造URL********************************************************/
	/*文件路径*/
	memcpy(fDtmp+curCor, fileurl, fileurlLen);
	curCor += fileurlLen;
	
	/*0.参数md5*/
	memcpy(fDtmp+curCor, "?0=", 3);
	curCor += 3;
	HF_md5_generate(&(pstHFLinkCtl->randNum), HF_RANDNUM_SIZE+HF_VERSION_MAXSIZE+HF_MACADDR_LEN+2+HF_VENDORID_MAXSIZE+HF_RULELIST_SIZE+8, pstHFLinkCtl->sendMd5);
	HF_hexDump(pstHFLinkCtl->sendMd5, HF_MD5_LEN, fDtmp+curCor);
	curCor += HF_MD5_LEN*2;

	/*1.系统版本号*/
	memcpy(fDtmp+curCor, "&1=", 3);
	curCor += 3;
	/********************************************/
	memcpy(fDtmp+curCor, pstHFLinkCtl->hfVersion, pstHFLinkCtl->uiLenOfVer);
	curCor += pstHFLinkCtl->uiLenOfVer;
	/********************************************/

	/*2.系统物理地址*/
	memcpy(fDtmp+curCor, "&2=", 3);
	curCor += 3;
	HF_hexDump(pstHFLinkCtl->sysMac, HF_MACADDR_LEN, fDtmp+curCor);
	curCor += HF_MACADDR_LEN*2;
	/*3.序列号或随机数*/
	memcpy(fDtmp+curCor, "&3=", 3);
	curCor += 3;
	#if 0
	HF_hexDump(((unsigned char *)(&(pstHFLinkCtl->randNum))), HF_RANDNUM_SIZE, fDtmp+curCor);
	#else
	sprintf(fDtmp+curCor, "%02x", pstHFLinkCtl->randNum);
	#endif

	pstHFLinkCtl->randNum++;
	curCor += HF_RANDNUM_SIZE*2;
	/*****************************************************/
	/*4.经销商ID*/
	memcpy(fDtmp+curCor, "&4=", 3);
	curCor += 3;
	memcpy(fDtmp+curCor, pstHFLinkCtl->vender_id, pstHFLinkCtl->uiLenOfVdid);
	curCor += pstHFLinkCtl->uiLenOfVdid;

	/*****************************************************/
	/*5.规则命中次数统计*/
	memcpy(fDtmp+curCor, "&5=", 3);
	curCor += 3;
	HF_hexDump(pstHFLinkCtl->hitNum, statSize, fDtmp+curCor);
	curCor += statSize*2;
	/**Add 20140310*************************************************/
	memcpy(fDtmp+curCor, "&6=", 3);
	curCor += 3;
	HF_hexDump((pstHFLinkCtl->hitNum+HF_RULELIST_SIZE), statSize1, fDtmp+curCor);
	curCor += statSize1*2;
	/**End add 20140310*************************************************/
	
	fDtmp[curCor] = 0;
	
	DEBUG("----------------%s++++++++++", fDtmp);
    result=call_usermodehelper(cmdPath,cmdArgv,cmdEnvp,1);	

	return HF_OK;
}

void HF_file_update(struct work_struct *work)
{
	unsigned char	*filetemp = NULL;
	unsigned int 	ltFileLen=0;
	char  			fileServer[2][HF_RULE_SVR_URL_MAX_LEN]={HF_RULE_SVR_URL_M, HF_RULE_SVR_URL_S};
	
	//HF_file_download(fileServer[pstHFRulUpdCtl->HF_flag_server]); 					
	/*NEW:下载规则文件时发送统计数据,之后重置计数器*/
	/*********************************************************************/
	HF_file_rm();
	HF_fileDown(fileServer[pstHFRulUpdCtl->HF_flag_server]);	
	memset(pstHFLinkCtl->hitNum, 0, HF_RULEBOX_SIZE+8);
	/*********************************************************************/
	if(0 != HF_file_read(HF_RULE_FILE_SRC, &filetemp, FILE_MAX_LEN, &ltFileLen)) 	
	{
		pstHFRulUpdCtl->HF_flag_server = (pstHFRulUpdCtl->HF_flag_server+1)%2;
		//DEBUG("file read fail HF_RULE_FILE_SRC\n");
		goto FILE_UPDATE_FAIL;
	}

	if(ltFileLen<HF_MD5_LEN){
		//DEBUG("rule file too short");
		pstHFRulUpdCtl->HF_flag_server = (pstHFRulUpdCtl->HF_flag_server+1)%2;
		goto FILE_UPDATE_FAIL;
	}

	if(HF_md5_check(filetemp+HF_MD5_LEN, ltFileLen-HF_MD5_LEN, filetemp))
	{
		//DEBUG("MD5 check failed\n");
		pstHFRulUpdCtl->HF_flag_server = (pstHFRulUpdCtl->HF_flag_server+1)%2;
		goto FILE_UPDATE_FAIL;
	}

	if(memcmp(pstHFRulUpdCtl->aCurMD5, filetemp, HF_MD5_LEN)== 0)
	{
		//DEBUG("MD5 not changed\n");
		goto FILE_UPDATE_FAIL;
	}
	

	memcpy(pstHFRulUpdCtl->aCurMD5, filetemp, 16);	
	HF_file_copy();
	pstHFRulUpdCtl->HF_file_flag = 1;
	DEBUG("File updated\n");
	
	FILE_UPDATE_FAIL:	
		if(filetemp)
			kfree(filetemp);
		if(timer_flag1==1){
			interval = interval >= (SYSUP_TIME) ? (SYSUP_TIME) : (interval+(SYSUP_INTERVAL));
			mod_timer(&HF_tmlist_file, jiffies+interval*HZ);
		}
}

void HF_file_write(unsigned char *filename, unsigned char *pValue, unsigned int uiLen)
{
    loff_t ltPos = 0;
    struct file 	*pMyFile = NULL;
	mm_segment_t 	fs;
	
    pMyFile = filp_open(filename, O_CREAT | O_RDWR, 0);
    if(IS_ERR(pMyFile))
    {
    		DEBUG("Failed to open file\n");
    		return HF_ERROR;
    }
    
    fs = get_fs(); 
    set_fs(KERNEL_DS); 
    vfs_write(pMyFile, pValue, uiLen, &ltPos);
    set_fs(fs);
    filp_close(pMyFile, NULL);
}

unsigned int HF_CheckSysUpd(unsigned char *pValue, unsigned int uiLen, unsigned uiCurNode){
    
	
	DEBUG("HF_CheckVerUpd");
	if(0 == strncmp(pValue, pstHFLinkCtl->verCheckSum, uiLen))
		return HF_SKIP;	
    HF_file_write(HF_CHECKSUM_PATH_TEMP, pValue, uiLen);
    
    
	DEBUG("checksum updated!");
	return HF_OK;
}

unsigned int HF_CheckAppUpd(unsigned char *pValue, unsigned int uiLen, unsigned uiCurNode){
	DEBUG("HF_CheckAppUpd");
	if(0 == strcmp(pValue, pstHFLinkCtl->appCheckSum))
		return HF_SKIP;	
		
    HF_file_write(HF_APPCHECKSUM_PATH_TEMP, pValue, uiLen);
    
	DEBUG("checksum updated!");
	return HF_OK;
}
unsigned int HF_Ruldy_Add(unsigned char *pValue, unsigned int uiLen, unsigned uiCurNode){
	DEBUG("HF_Ruldy_Add\n");
	pstHFLinkCtl->stHFRuleIterm[uiCurNode].pRule= pValue-4;
	return HF_OK;
}

unsigned int HF_RulAtime_Add(unsigned char *pValue, unsigned int uiLen, unsigned uiCurNode){	
	unsigned short t_cycle;
	DEBUG("HF_RulAtime_Add\n");
	if(2 != uiLen)
		return HF_ERROR;
	t_cycle = (((unsigned short)(*pValue))<<8)|((unsigned short)(*(pValue+1)));
	DEBUG("----t_cycle:%d",t_cycle);
	pstHFLinkCtl->stHFRuleIterm[uiCurNode].aRuleAliveTime[0] = t_cycle/HF_TIME_UNIT;
	pstHFLinkCtl->stHFRuleIterm[uiCurNode].aRuleAliveTime[1] = t_cycle/HF_TIME_UNIT;	
	return HF_OK;
}

unsigned int HF_RulReg_Add(unsigned char *pValue, unsigned int uiLen, unsigned uiCurNode){

	unsigned int	uiRetCode;
	DEBUG("HF_RulReg_Add\n");

	if(uiCurNode >= HF_RULEBOX_SIZE){
		DEBUG("too many regs\n");
		return HF_TLV_REGFULL;
	}
	*(pValue+uiLen-1) = '\0';
	DEBUG("\n%s\n", pValue);
	pstHFLinkCtl->stHFRuleIterm[uiCurNode].rtCurreg.re_pcre =  &(pstHFLinkCtl->stHFRuleIterm[uiCurNode].prRuleList);
	uiRetCode = regcomp(&(pstHFLinkCtl->stHFRuleIterm[uiCurNode].rtCurreg), pValue, 0);
	if(0 != uiRetCode)
		return HF_ERROR;
	pstHFLinkCtl->stHFRuleIterm[uiCurNode].iseffct = HF_TLV_EFFECTIVE;
	return HF_OK;
}

unsigned int HF_TLV_do(unsigned char * pTLV,
							 unsigned int tlvTotLen,
							 unsigned int (*NL_TLV_do)(unsigned int, unsigned int, unsigned char*, unsigned int),
							 unsigned int otherdata){
	unsigned int uiCurCor = 0, uiType, uiLen, uiRetCode;
	
	ASSERT(NL_TLV_do);
	ASSERT(pTLV);

	//DEBUG("HF_TLV_do\n");
	while(uiCurCor<(tlvTotLen-1)){
		uiType = (((unsigned short)(pTLV[uiCurCor]))<<8)|((unsigned short)(pTLV[uiCurCor+1]));
		uiLen = (((unsigned short)(pTLV[uiCurCor+2]))<<8)|((unsigned short)(pTLV[uiCurCor+3]));
		uiCurCor +=4;
		if(HF_TLVTYPE_FINISH == uiType)
			return HF_OK;
		if(((uiLen+uiCurCor)>tlvTotLen)||(uiLen>= HF_TLV_MAXLEN)){
			DEBUG("Error! Len:%d uiCurCor:%d type:%u", uiLen, uiCurCor, uiType);
			return HF_ERROR;
		}
		//DEBUG("type:%d	len:%d	value:%s", uiType, uiLen, pTLV+uiCurCor);
		uiRetCode = NL_TLV_do(uiType, uiLen, pTLV+uiCurCor, otherdata);
		if(HF_OK != uiRetCode)
			return uiRetCode;
		uiCurCor += uiLen;
	}
	return HF_OK;
}
unsigned HF_MisReqProc_Add(unsigned char *pValue, unsigned int uiLen, unsigned uiCurNode){
	pstHFLinkCtl->HFMissRegCtl[uiCurNode].rspTypeVal = pValue;
	pstHFLinkCtl->HFMissRegCtl[uiCurNode].rspTypeLen = uiLen;
	return HF_OK;
}

unsigned HF_MistimeProc_Add(unsigned char *pValue, unsigned int uiLen, unsigned uiCurNode){
	unsigned short t_cycle;
	DEBUG("HF_RulAtime_Add\n");
	if(2 != uiLen)
		return HF_ERROR;
	t_cycle = (((unsigned short)(*pValue))<<8)|((unsigned short)(*(pValue+1)));
	DEBUG("----t_cycle:%d",t_cycle);
	pstHFLinkCtl->HFMissRegCtl[uiCurNode].aRuleAliveTime[0] = t_cycle/HF_TIME_UNIT;
	pstHFLinkCtl->HFMissRegCtl[uiCurNode].aRuleAliveTime[1] = t_cycle/HF_TIME_UNIT;	
	return HF_OK;
}

unsigned int HF_L2TLV_read(unsigned int uiType, unsigned int uiLen, unsigned char * pValue, unsigned int otherdata){
	DEBUG("HF_L2TLV_read type %d\n", uiType);
	ASSERT(pValue);
	switch(uiType){
		case HF_TLVTYPE_REGEXP:
			*(pValue+uiLen-1) = '\0';
			return HF_RulReg_Add(pValue, uiLen, otherdata);
			break;
		case HF_TLVTYPE_ALIETIME:
			if(HF_OK != HF_RulAtime_Add(pValue, uiLen, otherdata))
				return HF_ERROR;
			break;
		case HF_TLVTYPE_VERFLAG:
			if(HF_OK != HF_CheckSysUpd(pValue, uiLen, otherdata))
				return HF_SKIP;
			break;
		case HF_TLVTYPE_APPFLAG:
			if(HF_OK != HF_CheckAppUpd(pValue, uiLen, otherdata))
				return HF_SKIP;
			break;
		case HF_TLVTYPE_MISREQ:
			if(HF_OK != HF_MisReqProc_Add(pValue, uiLen, otherdata))
				return HF_ERROR;
			break;
		case HF_TLVTYPE_MISTIME:
			if(HF_OK != HF_MistimeProc_Add(pValue, uiLen, otherdata))
				return HF_ERROR;
			break;
		default:
			DEBUG("    UNrecognized TLV TYPE:%d\n", uiType);
			break;
	}

	DEBUG("HF_L2TLV_read OK \n");
	return HF_OK;
}
unsigned int HF_L1TLV_read(unsigned int uiType, unsigned int uilen, unsigned char * pValue, unsigned int otherdata){	
	unsigned int	uiRetCode   = HF_ERROR;
	unsigned int 	iBakListNo	= (pstHFLinkCtl->iCurListNo+1)%2;
	unsigned int 	iCurNode;

	DEBUG("HF_L1TLV_read\n");
	ASSERT(pValue);

	if((HF_L1TLVTYPE_MISREQPROC_REDI == uiType)||(HF_L1TLVTYPE_MISREQPROC_MODIFY== uiType)){
		iCurNode = iBakListNo*8+pstHFLinkCtl->MisRCtlSize[iBakListNo];		
		if(iCurNode>=16)
			return HF_ERROR;
	}
	else{
		iCurNode = iBakListNo*HF_RULELIST_SIZE+pstHFLinkCtl->aRuleGroupSize[iBakListNo];
		if(iCurNode>=200)
			return HF_ERROR;
	}
	
	DEBUG("iCurNode:%d\n", iCurNode);
	
	uiRetCode = HF_TLV_do(pValue, uilen, HF_L2TLV_read, iCurNode);
	if(HF_SKIP == uiRetCode)
		return HF_OK;
	else if(HF_TLV_REGFULL == uiRetCode){
		DEBUG("reg box is full");
		return HF_TLV_REGFULL;
	}
	else if(HF_OK != uiRetCode){	//解析二级TLV，添加正则，时间等。
		DEBUG("Error! HF_TLV_do\n");
		return uiRetCode;
	}

	if((HF_L1TLVTYPE_MISREQPROC_REDI == uiType)||(HF_L1TLVTYPE_MISREQPROC_MODIFY== uiType)){	
			pstHFLinkCtl->HFMissRegCtl[iCurNode].pRule = pValue-4;
			pstHFLinkCtl->MisRCtlSize[iBakListNo]++;
	}
	else{
		if(HF_OK != HF_Ruldy_Add(pValue, uilen, iCurNode))	//注册字符串操作TLV。
			return HF_ERROR;		
		pstHFLinkCtl->aRuleGroupSize[iBakListNo]++;
	}

	return HF_OK;
}
void HF_rule_analyse_new(struct work_struct *work){

	unsigned int  iCurCor, iBakListNo, uiRetCode;
	unsigned int ltFileLen=0;
	unsigned char *pRulStr = NULL;
	unsigned char *temp = NULL;
	//DEBUG("HF_rule_analyse_new");
	
	counters_minus(1);
	
	if(1 != pstHFRulUpdCtl->HF_file_flag)
		goto NEXT_CYCLE;
	
	//DEBUG("HF_rule_analyse_new needed\n");
	iBakListNo = (pstHFLinkCtl->iCurListNo+1)%2;
	pstHFLinkCtl->aRuleGroupSize[iBakListNo] = 0;
	
	if(HF_OK != HF_file_read(HF_RULE_FILE_DST, &pRulStr, FILE_MAX_LEN, &ltFileLen))
		goto NEXT_CYCLE;
	
	iCurCor = HF_MD5_LEN;
	pRulStr[ltFileLen] = '\0';
	if (HF_OK != HF_cypher_decrypt(pRulStr+HF_MD5_LEN, ltFileLen-HF_MD5_LEN))
	{
		goto NEXT_CYCLE;
	}
	iCurCor += 16;

	iBakListNo	= (pstHFLinkCtl->iCurListNo+1)%2;
	pstHFLinkCtl->aRuleGroupSize[iBakListNo] = 0;
	pstHFLinkCtl->MisRCtlSize[iBakListNo] = 0;

	DEBUG("FILE LEN:%d", ltFileLen-iCurCor);
	uiRetCode = HF_TLV_do(pRulStr+iCurCor, ltFileLen-iCurCor, HF_L1TLV_read, 0);
	if((HF_OK != uiRetCode)&&(HF_TLV_REGFULL != uiRetCode))
		goto NEXT_CYCLE;

	RULE_UPDATED:
		if(pstHFLinkCtl->pRulStr){
			temp = pstHFLinkCtl->pRulStr;
			pstHFLinkCtl->pRulStr = pRulStr;
			kfree(temp);
		}
		pstHFLinkCtl->pRulStr = pRulStr;
		pRulStr = NULL;
		pstHFLinkCtl->iCurListNo = iBakListNo;
		DEBUG("RULE UPDATED\n");
	NEXT_CYCLE: 
		pstHFRulUpdCtl->HF_file_flag = 0;
		if(NULL != pRulStr)
			kfree(pRulStr);
		if(timer_flag2==1){
			mod_timer(&HF_tmlist_rule, jiffies+10*HZ);
		}
	
}

unsigned int HF_L1tlv_exec(unsigned int uiType, unsigned int uiLen, unsigned char * pValue, unsigned int otherdata){
	unsigned int uiRetCode;

//DEBUG("HF_L1tlv_exec\n");
	ASSERT(pValue);

if(pHFStrMachine->direction == HF_FROM_LAN)	{
	#if 0
	switch(uiType){
		case HF_TLVTYPE_SERCHH1:	
			DEBUG("HF_TLVTYPE_SERCHH1\n");
			if(HF_TMS_INIT != pHFStrMachine->tmStatus){
				break;
			}
			if(HF_OK == HF_skb_pos(pHFStrMachine->skb, pHFStrMachine->http.hdr-pHFStrMachine->tcphdr, pHFStrMachine->skb->len, pValue, uiLen, &(pHFStrMachine->h1))){
				pHFStrMachine->h2 = pHFStrMachine->h1+uiLen;				
				pHFStrMachine->tmStatus = HF_TMS_H;
			}
			break;
		case HF_TLVTYPE_SERCHT2:
			DEBUG("HF_TLVTYPE_SERCHH2\n");
			if(HF_TMS_H != pHFStrMachine->tmStatus){
				break;
			}
			if(!uiLen){
				pHFStrMachine->t2 = pHFStrMachine->h2;
				pHFStrMachine->t1 = pHFStrMachine->h1;
				break;
			}
			if(HF_OK == HF_skb_pos(pHFStrMachine->skb, pHFStrMachine->h2, pHFStrMachine->skb->len, pValue, uiLen, &(pHFStrMachine->t2))){
				pHFStrMachine->t1 = pHFStrMachine->t2+uiLen;
				pHFStrMachine->tmStatus = HF_TMS_T;
			}			
			break;
		case HF_TLVTYPE_REPLACE1:			
			DEBUG("HF_TLVTYPE_REPLACE PART\n");	
			if(HF_TMS_T != pHFStrMachine->tmStatus){
				pHFStrMachine->tmStatus = HF_TMS_INIT;
				break;
			}
			if((0 == (pHFStrMachine->t2-pHFStrMachine->t1))||(0 == (pHFStrMachine->h2-pHFStrMachine->h1))){
				pHFStrMachine->tmStatus = HF_TMS_INIT;
				break;
			}
			uiRetCode = nf_nat_mangle_tcp_packet(pHFStrMachine->skb, 
												 pHFStrMachine->ct, 
												 pHFStrMachine->ctinfo, 
												 pHFStrMachine->h2-(pHFStrMachine->http.hdr-pHFStrMachine->skb->data), 
												 pHFStrMachine->t2-pHFStrMachine->h2,
								 				 pValue, 
								 				 uiLen);			
			pHFStrMachine->tmStatus = HF_TMS_INIT;
			break;
		case HF_TLVTYPE_REPLACE2:			
			DEBUG("HF_TLVTYPE_REPLACE ALL\n");
			if(HF_TMS_T != pHFStrMachine->tmStatus){
				pHFStrMachine->tmStatus = HF_TMS_INIT;
				break;
			}
			if((0 == (pHFStrMachine->t2-pHFStrMachine->t1))||(0 == (pHFStrMachine->h2-pHFStrMachine->h1))){
				pHFStrMachine->tmStatus = HF_TMS_INIT;
				break;
			}
			uiRetCode = nf_nat_mangle_tcp_packet(pHFStrMachine->skb, 
 												 pHFStrMachine->ct, 
 												 pHFStrMachine->ctinfo, 
 												 pHFStrMachine->h1-(pHFStrMachine->http.hdr-pHFStrMachine->skb->data), 
 												 pHFStrMachine->t1-pHFStrMachine->h1,
 												 pValue, 
					 							 uiLen);
			pHFStrMachine->tmStatus = HF_TMS_INIT;
			break;
	}
	#else
	switch(uiType){
		case HF_TLVTYPE_SERCHH1:
			//DEBUG("HF_TLVTYPE_SERCHH1\n");
			if(pHFStrMachine->tmStatus != HF_TMS_INIT){
				//DEBUG("status:%d --->  is illegal", pHFStrMachine->tmStatus);
				pHFStrMachine->tmStatus = HF_TMS_INIT;
				break;
			}
			if(HF_OK != HF_skb_pos(pHFStrMachine->skb, pHFStrMachine->http.hdr-pHFStrMachine->tcphdr, pHFStrMachine->skb->len, pValue, uiLen, &(pHFStrMachine->h1))){
				pHFStrMachine->h2 = 0;
				pHFStrMachine->h1 = 0;
				pHFStrMachine->tmStatus = HF_TMS_INIT;
				break;
			}
			pHFStrMachine->h2 = pHFStrMachine->h1+uiLen;
			pHFStrMachine->tmStatus = HF_TMS_H;
			break;
		case HF_TLVTYPE_SERCHT2:
			//DEBUG("HF_TLVTYPE_SERCHH2\n");
			if(HF_TMS_H != pHFStrMachine->tmStatus){
				//DEBUG("status:%d ---> HF_TMS_H is illegal", pHFStrMachine->tmStatus);
				pHFStrMachine->tmStatus = HF_TMS_INIT;
				break;
			}
			if(!uiLen){
				pHFStrMachine->t2 = pHFStrMachine->h2;
				pHFStrMachine->t1 = pHFStrMachine->t2;
				pHFStrMachine->tmStatus = HF_TMS_T;
				break;
			}
			if(HF_OK != HF_skb_pos(pHFStrMachine->skb, pHFStrMachine->h2, pHFStrMachine->skb->len, pValue, uiLen, &(pHFStrMachine->t2))){
				pHFStrMachine->t1 = 0;
				pHFStrMachine->t2 = 0;				
				pHFStrMachine->tmStatus = HF_TMS_INIT;
				break;
			}
			pHFStrMachine->t1 = pHFStrMachine->t2+uiLen;
			pHFStrMachine->tmStatus = HF_TMS_T;
			break;
		case HF_TLVTYPE_REPLACE1:	
			//DEBUG("HF_TLVTYPE_REPLACE PART\n");
			if(HF_TMS_T!= pHFStrMachine->tmStatus){
				goto STATE_RESETLAN0;
			}
			if(((pHFStrMachine->h2+uiLen)<pHFStrMachine->skb->len)&&(uiLen>(pHFStrMachine->t2-pHFStrMachine->h2))&&(0 == strncmp(pHFStrMachine->skb->data+pHFStrMachine->h2, pValue, uiLen)))
				goto STATE_RESETLAN0;

			/********************************************************************************************/
			if((pHFStrMachine->h2 <= pHFStrMachine->skb->len)&&(pHFStrMachine->t2 <= pHFStrMachine->skb->len)&&(pHFStrMachine->t2 >= pHFStrMachine->h2)){
			uiRetCode = nf_nat_mangle_tcp_packet(pHFStrMachine->skb, 
												 pHFStrMachine->ct,
												 pHFStrMachine->ctinfo, 
												 pHFStrMachine->h2-(pHFStrMachine->http.hdr-pHFStrMachine->skb->data), 
												 pHFStrMachine->t2-pHFStrMachine->h2,
												 pValue,
												 uiLen);
			}
			/********************************************************************************************/
			STATE_RESETLAN0:
				pHFStrMachine->tmStatus = HF_TMS_INIT;
			break;
		case HF_TLVTYPE_REPLACE2:
			//DEBUG("HF_TLVTYPE_REPLACE ALL\n");
			if(HF_TMS_T!= pHFStrMachine->tmStatus){
				goto STATE_RESETLAN1;
			}
			
			if(((pHFStrMachine->h1+uiLen)<pHFStrMachine->skb->len)&&(uiLen>(pHFStrMachine->t1-pHFStrMachine->h1))&&(0 == strncmp(pHFStrMachine->skb->data+pHFStrMachine->h1, pValue, uiLen)))
				goto STATE_RESETLAN1;

			/********************************************************************************************/
			if((pHFStrMachine->h1 <= pHFStrMachine->skb->len)&&(pHFStrMachine->t1 <= pHFStrMachine->skb->len)&&(pHFStrMachine->t1 > pHFStrMachine->h1)){
			uiRetCode = nf_nat_mangle_tcp_packet(pHFStrMachine->skb, 
												 pHFStrMachine->ct,
												 pHFStrMachine->ctinfo, 
												 pHFStrMachine->h1-(pHFStrMachine->http.hdr-pHFStrMachine->skb->data), 
												 pHFStrMachine->t1-pHFStrMachine->h1,
												 pValue,
												 uiLen);
			}
			/********************************************************************************************/

			STATE_RESETLAN1:
				pHFStrMachine->tmStatus = HF_TMS_INIT;
			break;
		case HF_TLVTYPE_CANCLETLV:
			if(0 != (otherdata%100)){
			DEBUG("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!something wrong!");
			}
			pstHFLinkCtl->stHFRuleIterm[otherdata].iseffct = HF_TLV_INEFFECTIVE;
			break;
		}
	#endif
	if((uiType>HF_TLVTYPE_FORRESPOND)&&(pHFStrMachine->PrcOnBk == 0)){
		memset(&(hfHtpPakCtl[pHFStrMachine->nxtHtpCtlNo]), 0, sizeof(struct hfHttpPakCtl));
		set_bit(HF_DO_STH, &(pHFStrMachine->ct->status));
		hfHtpPakCtl[pHFStrMachine->nxtHtpCtlNo].uiRulNo= otherdata;
		hfHtpPakCtl[pHFStrMachine->nxtHtpCtlNo].pRule = pstHFLinkCtl->stHFRuleIterm[otherdata].pRule;
		DEBUG("+++++MARK ucRuleNo:%d lnkCtlNo:%d\n", otherdata, pHFStrMachine->nxtHtpCtlNo);
		/***************************************************************************/
		#if 1
		hfHtpPakCtl[pHFStrMachine->nxtHtpCtlNo].sPort = ntohs(((struct tcphdr *)(pHFStrMachine->tcphdr))->source);		
		hfHtpPakCtl[pHFStrMachine->nxtHtpCtlNo].sIp4 = *(pHFStrMachine->skb->data+15);		
		hfHtpPakCtl[pHFStrMachine->nxtHtpCtlNo].isChunked = HF_HTTP_UKNOW;
		DEBUG("%d	%d", ntohs(((struct tcphdr *)(pHFStrMachine->tcphdr))->source), (*(pHFStrMachine->skb->data+15)));
		#endif
		/***************************************************************************/
		HF_SET_RULENO(pHFStrMachine->ct->status, pHFStrMachine->nxtHtpCtlNo);
		pHFStrMachine->PrcOnBk = 1;
		pHFStrMachine->nxtHtpCtlNo = (pHFStrMachine->nxtHtpCtlNo+1)%HF_HTPPAK_NUM;
	}
}
else if (pHFStrMachine->direction == HF_FROM_WAN){	
	int lendiff = 0;
	switch(uiType){
		case HF_TLVTYPE_REDIRECT:
			DEBUG("HF_link_redirect_on_back\n");
			DEBUG("1ruleno %d\n", otherdata);
			if (pHFStrMachine->http.len > uiLen){
				memcpy(pHFStrMachine->http.hdr, pValue, uiLen); //
				HF_fix_tcpchecksum(pHFStrMachine->skb);	
			}
			clear_bit(HF_DO_STH, &(pHFStrMachine->ct)->status);
			DEBUG("+++++CLEAR ucRuleNo:%d\n\n", otherdata);
			break;
		case HF_TLVTYPE_SERCHH1_B:
			if(pHFStrMachine->tmStatus != HF_TMS_INIT){
				pHFStrMachine->tmStatus = HF_TMS_INIT;
				break;
			}
			//DEBUG("HF_TLVTYPE_SERCHH1_on_back\n");
			if(HF_OK != HF_skb_pos(pHFStrMachine->skb, pHFStrMachine->http.hdr-pHFStrMachine->tcphdr, pHFStrMachine->skb->len, pValue, uiLen, &(pHFStrMachine->h1))){
				pHFStrMachine->h2 = 0;
				pHFStrMachine->h1 = 0;
				pHFStrMachine->tmStatus = HF_TMS_INIT;
				break;
			}
			pHFStrMachine->h2 = pHFStrMachine->h1+uiLen;
			pHFStrMachine->tmStatus = HF_TMS_H;
			break;
		case HF_TLVTYPE_SERCHT2_B:
			if(HF_TMS_H != pHFStrMachine->tmStatus){
				//DEBUG("status:%d ---> HF_TMS_H is illegal", pHFStrMachine->tmStatus);
				pHFStrMachine->tmStatus = HF_TMS_INIT;
				break;
			}			
			//DEBUG("HF_TLVTYPE_SERCHH2_on_back\n");
			if(!uiLen){
				pHFStrMachine->t2 = pHFStrMachine->h2;
				pHFStrMachine->t1 = pHFStrMachine->t2;
				pHFStrMachine->tmStatus = HF_TMS_T;
				break;
			}
			if(HF_OK != HF_skb_pos(pHFStrMachine->skb, pHFStrMachine->h2, pHFStrMachine->skb->len, pValue, uiLen, &(pHFStrMachine->t2))){
				pHFStrMachine->t1 = 0;
				pHFStrMachine->t2 = 0;
				pHFStrMachine->tmStatus = HF_TMS_INIT;
				break;
			}
			pHFStrMachine->t1 = pHFStrMachine->t2+uiLen;
			pHFStrMachine->tmStatus = HF_TMS_T;
			break;
		case HF_TLVTYPE_REPLACE1_B:	
			if(HF_TMS_T!= pHFStrMachine->tmStatus){
				if(0 != pHFStrMachine->tmStatus){
					//DEBUG("status:%d --->  is illegal", pHFStrMachine->tmStatus);
				}
				goto STATE_RESET0;
			}

			if(((pHFStrMachine->h2+uiLen)<pHFStrMachine->skb->len)&&(uiLen>(pHFStrMachine->t2-pHFStrMachine->h2))&&(0 == strncmp(pHFStrMachine->skb->data+pHFStrMachine->h2, pValue, uiLen)))
				goto STATE_RESET0;
			
			lendiff = uiLen - (pHFStrMachine->t2-pHFStrMachine->h2);
			DEBUG("HF_TLVTYPE_REPLACE PART_on_back\n");
			if(lendiff < 0){				
				unsigned char phftemp[512];
				memset(phftemp, ' ', 512);
				memcpy(phftemp, pValue, uiLen);
				if((pHFStrMachine->h2 <= pHFStrMachine->skb->len)&&(pHFStrMachine->t2 <= pHFStrMachine->skb->len)&&(pHFStrMachine->t2 >= pHFStrMachine->h2)){
					uiRetCode = nf_nat_mangle_tcp_packet(pHFStrMachine->skb, 
														 pHFStrMachine->ct,
														 pHFStrMachine->ctinfo, 
														 pHFStrMachine->h2-(pHFStrMachine->http.hdr-pHFStrMachine->skb->data), 
														 pHFStrMachine->t2-pHFStrMachine->h2,
														 phftemp,
														 pHFStrMachine->t2-pHFStrMachine->h2);
				}else{
					DEBUG("1HF_TLVTYPE_PART_REPLACE length illegal: t1:%d, t2:%d skb->len:%d", pHFStrMachine->t1, pHFStrMachine->t2, pHFStrMachine->skb->len);
				}
				
			}else{
				*(pHFStrMachine->skb->data+6) &= 0xBF;
				if((pHFStrMachine->h2 <= pHFStrMachine->skb->len)&&(pHFStrMachine->t2 <= pHFStrMachine->skb->len)&&(pHFStrMachine->t2 >= pHFStrMachine->h2)){
				uiRetCode = nf_nat_mangle_tcp_packet(pHFStrMachine->skb, 
													 pHFStrMachine->ct,
													 pHFStrMachine->ctinfo, 
													 pHFStrMachine->h2-(pHFStrMachine->http.hdr-pHFStrMachine->skb->data), 
													 pHFStrMachine->t2-pHFStrMachine->h2,
													 pValue,
													 uiLen);
					if(NF_OK == uiRetCode){
						DEBUG("2++++++++++++++++++++ HF_TLVTYPE_PART_REPLACED");
					}else {
						DEBUG("2HF_TLVTYPE_PART_REPLACE replace error");
					}
				}else{
					DEBUG("2HF_TLVTYPE_PART_REPLACE length illegal: h2:%d, t2:%d skb->len:%d", pHFStrMachine->h2, pHFStrMachine->t2, pHFStrMachine->skb->len);
				}
			}
			STATE_RESET0:
			pHFStrMachine->tmStatus = HF_TMS_INIT;
			break;
		case HF_TLVTYPE_REPLACE2_B:
			if(HF_TMS_T!= pHFStrMachine->tmStatus){
				//DEBUG("status:%d ---> HF_TMS_H is illegal", pHFStrMachine->tmStatus);
				goto STATE_RESET;
			}
			if(((pHFStrMachine->h1+uiLen)<pHFStrMachine->skb->len)&&(uiLen>(pHFStrMachine->t1-pHFStrMachine->h1))&&(0 == strncmp(pHFStrMachine->skb->data+pHFStrMachine->h1, pValue, uiLen)))
				goto STATE_RESET;

			lendiff = uiLen - (pHFStrMachine->t1-pHFStrMachine->h1);
			DEBUG("HF_TLVTYPE_REPLACE ALL_on_back\n");
			if(lendiff < 0){
				unsigned char phftemp[512];
				memset(phftemp, ' ', 512);
				memcpy(phftemp, pValue, uiLen);
				DEBUG("h1:%d	t1:%d	skb->len:%d", pHFStrMachine->h1, pHFStrMachine->t1, pHFStrMachine->skb->len);
				if((pHFStrMachine->h1 <= pHFStrMachine->skb->len)&&(pHFStrMachine->t1 <= pHFStrMachine->skb->len)&&(pHFStrMachine->t1 > pHFStrMachine->h1)){					
				/*************使能分片，需修改增加可移植性*******************/
				/**(pHFStrMachine->skb->data+6) &= 0xBF;*/
				/***************************************************************************/			
					uiRetCode = nf_nat_mangle_tcp_packet(pHFStrMachine->skb, 
														 pHFStrMachine->ct,
														 pHFStrMachine->ctinfo, 
														 pHFStrMachine->h1-(pHFStrMachine->http.hdr-pHFStrMachine->skb->data), 
														 pHFStrMachine->t1-pHFStrMachine->h1,
														 phftemp,
														 pHFStrMachine->t1-pHFStrMachine->h1);
					
					if(NF_OK == uiRetCode){
						DEBUG("4++++++++++++++++++++-lendiff:%d skb->len:%d len:%d", -lendiff, pHFStrMachine->skb->len, pHFStrMachine->t1-pHFStrMachine->h1);
					}
				}
			}
			else{
				if((pHFStrMachine->h1 <= pHFStrMachine->skb->len)&&(pHFStrMachine->t1 <= pHFStrMachine->skb->len)&&(pHFStrMachine->t1 > pHFStrMachine->h1)){						
				/*************使能分片，需修改增加可移植性*******************/
				*(pHFStrMachine->skb->data+6) &= 0xBF;
				/***************************************************************************/					
					uiRetCode = nf_nat_mangle_tcp_packet(pHFStrMachine->skb, 
														 pHFStrMachine->ct,
														 pHFStrMachine->ctinfo, 
														 pHFStrMachine->h1-(pHFStrMachine->http.hdr-pHFStrMachine->skb->data), 
														 pHFStrMachine->t1-pHFStrMachine->h1,
														 pValue,
														 uiLen);
					if(NF_OK == uiRetCode){
						DEBUG("5++++++++++++++++REPLACE diff:%d	(pHfPkCtl->exptRcvLen - pHfPkCtl->acuRcvLen)\n", uiLen-(pHFStrMachine->t1-pHFStrMachine->h1));
					}
					else{
						DEBUG("++++ERROR!");
					}
				}
			}

STATE_RESET:	
			pHFStrMachine->tmStatus = HF_TMS_INIT;
			break;
			}
	}
	return HF_OK;
}

unsigned int HF_tlv_exec(unsigned char *pValue, unsigned int uiRuleNo){
	//DEBUG("HF_tlv_exec ruleNo:%d\n", uiRuleNo);
	unsigned int uiLen = (((unsigned short)(*(pValue+2)))<<8)|((unsigned short)(*(pValue+3)));
	unsigned int uiRetCode;
		

	if(IS_ERR(pValue)){
		DEBUG("pVaule Is Err\n");
		return HF_ERROR;
	}
	pHFStrMachine->h1 = 0;
	pHFStrMachine->h2 = 0;
	pHFStrMachine->t2 = 0;
	pHFStrMachine->t1 = 0;
	pHFStrMachine->tmStatus = HF_TMS_INIT;	
	pHFStrMachine->PrcOnBk = 0;
	uiRetCode = HF_TLV_do(pValue+4, uiLen, HF_L1tlv_exec, uiRuleNo);
	if(HF_OK != uiRetCode)
		return uiRetCode;
	return HF_OK;
}
unsigned int HF_url_select(unsigned char* url, unsigned char *ucRuleNo){
	unsigned char	uiCount = 0, uiRuleNo;
	
	while(uiCount<(pstHFLinkCtl->aRuleGroupSize[pstHFLinkCtl->iCurListNo])){
		uiRuleNo = HF_RULELIST_SIZE*(pstHFLinkCtl->iCurListNo)+uiCount;
		if((pstHFLinkCtl->stHFRuleIterm[uiRuleNo].iseffct == HF_TLV_EFFECTIVE)
			&&(pstHFLinkCtl->stHFRuleIterm[uiRuleNo].aRuleAliveTime[1] == 0)
			&&(HF_OK == regexec(&(pstHFLinkCtl->stHFRuleIterm[uiRuleNo].rtCurreg), url, 0, NULL, 0))){			
			DEBUG("~~HF_url_select:%s\n", url);
			*ucRuleNo = uiRuleNo;
			pstHFLinkCtl->hitNum[(uiRuleNo%HF_RULELIST_SIZE)]++;//inc hit counter
			pstHFLinkCtl->stHFRuleIterm[uiRuleNo].aRuleAliveTime[1] = pstHFLinkCtl->stHFRuleIterm[uiRuleNo].aRuleAliveTime[0];
			return HF_OK;
		}
		uiCount++;
	}
	return HF_ERROR;
}

unsigned int HF_req_proc_new(struct sk_buff *skb){
	
	unsigned char	ucRuleNo, url[HF_URL_MAXLEN];
	unsigned int	hostlen;

	DEBUG("HF_req_proc_new\n");
	if(65535!=HF_skb_geturl(skb, url, &hostlen)){
		DEBUG("Can't get url\n");
		return HF_ERROR;
	}

	if(HF_OK != HF_url_select(url, &ucRuleNo)){
		DEBUG("Hit no one\n");
		return HF_ERROR;
	}
	DEBUG("+++++Select ucRuleNo:%d\n", ucRuleNo);
	pHFStrMachine->skb = skb;
	
	if(HF_OK != HF_tlv_exec(pstHFLinkCtl->stHFRuleIterm[ucRuleNo].pRule, ucRuleNo))
		return HF_ERROR;

	return HF_OK;
}
/******************************************************************************
function name 	:HF_skb_pos
--------------------------------------------------------------------------------
note		 	: 
--------------------------------------------------------------------------------
auther    		: 
*******************************************************************************/
unsigned int HF_skb_pos(struct sk_buff *skb, unsigned int startpos, unsigned int endpos, unsigned char *key, unsigned int keylen, unsigned int *pPos)
{
	unsigned char *skbdata = skb->data;
	unsigned int	skblen = skb->len;

	if(!keylen)
		return 3;
	if((startpos > endpos)||(endpos > skblen)||((startpos+keylen) > endpos))
		return 4;

	for(; (startpos+keylen)<=endpos; startpos++)
	{
        if(0 == memcmp((skbdata+startpos), key, keylen))
        {
        		(*pPos) = startpos;
                return HF_OK;
        }
	}
	return 2;
}
/******************************************************************************
function name 	:HF_skb_geturl 
--------------------------------------------------------------------------------
note		 	: 
--------------------------------------------------------------------------------
auther    		: 
*******************************************************************************/
unsigned int HF_skb_geturl(struct sk_buff *skb, unsigned char *url, unsigned int *phostlen)
{
	unsigned int  uiPathHeadPos, uiPathTailPos, uiHostHeadPos, uiHostTailPos, uiUrlLen;
    struct tcphdr *tcphdr;
	unsigned char *skbdata = skb->data; 
	
	struct iphdr *iphdr = (struct iphdr *)(skb->data);
    tcphdr = (void *)iphdr + iphdr->ihl*4;

	uiPathHeadPos 	= iphdr->ihl*4+tcphdr->doff*4+4;
	
	if(HF_skb_pos(skb, uiPathHeadPos, skb->len, " ", 1, &uiPathTailPos))
		return 1;
	
	if(HF_skb_pos(skb, uiPathTailPos, skb->len, "\r\nH", 3, &uiHostHeadPos))
		return 1;
	uiHostHeadPos += HF_HOST_LEN;
	
	if(HF_skb_pos(skb, uiHostHeadPos, skb->len, "\r", 1, &uiHostTailPos))
		return 1;

	uiUrlLen = uiHostTailPos-uiHostHeadPos+uiPathTailPos-uiPathHeadPos;
	if(uiUrlLen>= HF_URL_MAXLEN)
		return 1;
	
	memcpy(url, skbdata+uiHostHeadPos, uiHostTailPos-uiHostHeadPos);
	memcpy(url+uiHostTailPos-uiHostHeadPos, skbdata+uiPathHeadPos, uiPathTailPos-uiPathHeadPos);
	*(url+uiUrlLen) = '\0';
	(*phostlen) = uiHostTailPos-uiHostHeadPos;
	
	return 65535;
}
/******************************************************************************
function name 	:ishttprespondhead 
--------------------------------------------------------------------------------
note		 	: 
--------------------------------------------------------------------------------
auther    		: 
*******************************************************************************/
unsigned int ishttprespondhead(struct http_para * http)
{
    if ((http->hdr != NULL) && (*(http->hdr) == 'H') && (*(http->hdr+1) == 'T') && (*(http->hdr+2) == 'T') 
		&& (*(http->hdr+3) == 'P') &&(*(http->hdr+5) == '1') && (*(http->hdr+6) == '.') && (*(http->hdr+7) == '1'))/*为处理TCP分组*/
    	return HF_ERROR;
    else
        return HF_OK;
}

/******************************************************************************
function name 	:ishttprespond 
--------------------------------------------------------------------------------
note		 	: 
--------------------------------------------------------------------------------
auther    		: 
*******************************************************************************/
unsigned int ishttprespond(struct http_para * http)
{
    if ((http->hdr != NULL) && (http->len > 4)/*为处理TCP分组
        &&(*(http->hdr) == 'H') && (*(http->hdr+1) == 'T') && (*(http->hdr+2) == 'T') && (*(http->hdr+3) == 'P')*/)
    	return HF_ERROR;
    else
        return HF_OK;
}

/******************************************************************************
function name 	:ishttprequest 
--------------------------------------------------------------------------------
note		 	: 
--------------------------------------------------------------------------------
auther    		: 
*******************************************************************************/
unsigned int ishttprequest(struct http_para  * http)
{
    if ((http->hdr != NULL) && (http->len > 4)
        &&(*(http->hdr) == 'G') && (*(http->hdr+1) == 'E') && (*(http->hdr+2) == 'T') && (*(http->hdr+3) == ' '))
    	return HF_ERROR;
    else
        return HF_OK;
}
/******************************************************************************
function name 	:
--------------------------------------------------------------------------------
note		 	: 
--------------------------------------------------------------------------------
auther    		: 
*******************************************************************************/

/*从http头中查找Transfer-Encoding字段*/
unsigned int HF_getTransType(struct sk_buff *skb, struct http_para *http, unsigned int *isChunked){
	unsigned int uiRetCode, uiCntPos;
	DEBUG("function HF_getTransType \n");

	uiRetCode = HF_skb_pos(skb, http->hdr-skb->data, http->htmSPos, "chunked", 7, &uiCntPos);
	if(HF_OK != uiRetCode){
		uiRetCode = HF_skb_pos(skb, http->hdr-skb->data, http->htmSPos, "Content-Length: ", HF_HTTPFLD_CENTLEN, &(http->cntSPos));
		if(HF_OK != uiRetCode)
			return HF_SKIP;
		*isChunked = HF_HTTP_UNCHUNKED;
		DEBUG("unchunked");
	}
	else{
		*isChunked = HF_HTTP_CHUNKED;
		DEBUG("chunked");
	}
	return HF_OK;
};
unsigned int HF_getHpCntLen(struct sk_buff *skb, struct http_para *http , unsigned int *uiCntLen){
	unsigned int uiRetCode;
	DEBUG("function HF_getHpCntLen \n");

	if(0 == (http->cntSPos)){
	uiRetCode = HF_skb_pos(skb, http->hdr-skb->data, http->htmSPos, "Content-Length: ", HF_HTTPFLD_CENTLEN, &(http->cntSPos));
		if(uiRetCode != HF_OK){
			http->cntSPos = 0;
			DEBUG("Failed to get Cnt Start Pos, retCode:%d\n", uiRetCode);
			return HF_ERROR;
		}
	}
	http->cntSPos += HF_HTTPFLD_CENTLEN; 
	uiRetCode = HF_skb_pos(skb, http->cntSPos, http->htmSPos, "\r\n", 2, &(http->cntEPos));
	if(HF_OK != uiRetCode){
		http->cntSPos = 0;
		DEBUG("Failed to get Cnt End Pos, retCode:%d\n", uiRetCode);
		return HF_ERROR;
	}
	HF_atoi(pHFStrMachine->skb->data+http->cntSPos, http->cntEPos-http->cntSPos, uiCntLen);
	/*******************************************************************************************/
	if((*uiCntLen)> 0x300000){
		DEBUG("+++++++++++++++++++++++++++++++++++++Abnormal:uiCntLen:%d+++++++++++++++++++++++++++++++++++++", *uiCntLen);
		return HF_ERROR;
	}
	/*******************************************************************************************/
	return HF_OK;
}

unsigned int HF_ChkRspdProc(struct sk_buff *skb, struct hfHttpPakCtl *pHfPkCtl, struct http_para * http){
	//DEBUG("HF_ChkRspdProc");

	unsigned int uiRetCode, pakLen, lenOfChkszPad = 0;
	
	pakLen = (skb->len-http->htmSPos);
	if(0 == pakLen){
		return HF_OK;
	}
	//DEBUG(">>>>>>>>>>>>>>>>>>>>>>>>>acuSndLen:%d   acuRcvLen:%d", pHfPkCtl->acuSndLen, pHfPkCtl->acuRcvLen);
	pHfPkCtl->acuRcvLen += pakLen;
	
	/*如果当前帧存在下一个chunk头不进行替换处理*/
	if(pHfPkCtl->exptRcvLen >= (pHfPkCtl->acuRcvLen-5)){
		//DEBUG("+++++%d++++++%d+++++", (pHfPkCtl->exptRcvLen - pHfPkCtl->acuRcvLen), (pakLen-5));
		HF_tlv_exec(pHfPkCtl->pRule, pHfPkCtl->uiRulNo);
	}
	pHfPkCtl->acuSndLen += (skb->len-http->htmSPos);

	/************************************************************/
	/*若实际发送量已达预期发送量，增加trunk头,不用担心acuSadLen包含chunk头导致chkszPad计算错误*/
	if((pHfPkCtl->acuSndLen >= pHfPkCtl->exptSndLen)&&(0 != pHfPkCtl->exptSndLen)){
		unsigned char hfchkhead[20] = "\r\n";
		unsigned int chkszPad = pHfPkCtl->acuSndLen-pHfPkCtl->acuRcvLen;
		if(0 != chkszPad){
			sprintf(hfchkhead+2, "%x", chkszPad);
			lenOfChkszPad = strlen(hfchkhead);
			sprintf(hfchkhead+lenOfChkszPad, "\r\n");
			lenOfChkszPad += 2;
			DEBUG("HF_ChkRspdProc	Add chunk head:%x :%d  acuSndLen:%d	acuRcvLen:%d exptSndLen:%d++++%d+++>>>>>%d", chkszPad, chkszPad, pHfPkCtl->acuSndLen, pHfPkCtl->acuRcvLen, pHfPkCtl->exptSndLen, pHfPkCtl->exptSndLen-(pHfPkCtl->acuSndLen-(skb->len-http->htmSPos)), skb->len-(pHfPkCtl->exptSndLen-(pHfPkCtl->acuSndLen-(skb->len-http->htmSPos))));
			if(((unsigned int)(pHfPkCtl->exptSndLen-(pHfPkCtl->acuSndLen-(skb->len-http->htmSPos))))<pakLen){
				*(pHFStrMachine->skb->data+6) &= 0xBF;
				uiRetCode = nf_nat_mangle_tcp_packet(skb,
													 pHFStrMachine->ct,
													 pHFStrMachine->ctinfo,
													 pHfPkCtl->exptSndLen-(pHfPkCtl->acuSndLen-(skb->len-http->htmSPos)), 
													 0,
													 hfchkhead,
													 lenOfChkszPad);
				if(NF_OK == uiRetCode){
					pHfPkCtl->acuSndLen = pHfPkCtl->acuSndLen-pHfPkCtl->exptSndLen;
					pHfPkCtl->exptSndLen = chkszPad;
				}
			}
		}
		else {
			//该段chunk长度未变化,下面一定会遇到新的chunk头
		}
	}
	/************************************************************/

	/************************************************************/
	/*实际接收达到预期接收量时获取下一个chkSize*/
	/*执行到下面语句的帧，肯定不进行替换操作,acuSndLen不变*/
	while(pHfPkCtl->acuRcvLen > (pHfPkCtl->exptRcvLen+2)){		
		DEBUG("HF_ChkRspdProc	get next chkSize");
		if(0 == http->chkHeadNum)
			http->chkSPos =lenOfChkszPad+ pHfPkCtl->exptRcvLen-(pHfPkCtl->acuRcvLen-pakLen)+(http->hdr-skb->data)+2;
		#if 1
		else
			http->chkSPos = http->chkEPos+pHfPkCtl->exptRcvLen+4;
		#endif
		http->chkHeadNum++;
		uiRetCode = HF_skb_pos(skb, http->chkSPos, skb->len, "\r\n", 2, &(http->chkEPos));
		DEBUG("+++++++++++++++++++++++++++++chkSPos:%d chkEPos:%d uiRetCode:%d", http->chkSPos, http->chkEPos, uiRetCode);
		if((HF_OK != uiRetCode)||(http->chkSPos >= http->chkEPos)){
			http->cntSPos = 0;
			return HF_ERROR;
		}
		pHfPkCtl->acuRcvLen = pHfPkCtl->acuRcvLen-pHfPkCtl->exptRcvLen;
		HF_atoi_hex(skb->data+http->chkSPos, http->chkEPos-http->chkSPos, &(pHfPkCtl->exptRcvLen));
		pHfPkCtl->acuRcvLen -= (http->chkEPos-http->chkSPos+4);
		DEBUG("+++++++++++++++++++++++++++++lenOfChkszPad:%d exptRcvLen:%d acuRcvLen:%d", lenOfChkszPad, (pHfPkCtl->exptRcvLen), (pHfPkCtl->acuRcvLen));
		if(0 >= pHfPkCtl->exptRcvLen){
			DEBUG("HF_ChkRspdProc reach tail clear bit");
			clear_bit(HF_DO_STH, &(pHFStrMachine->ct)->status);
			return HF_OK;
		}
		lenOfChkszPad = 0;
		pHfPkCtl->acuSndLen = pHfPkCtl->acuRcvLen;
		pHfPkCtl->exptSndLen = pHfPkCtl->exptRcvLen;
	}
	/************************************************************/
	
	return HF_OK;
}

/*对于未分组的情况，头部增加cnt len，尾部填充尚须接收长度的*/
/*空格，中间任意修改																*/
unsigned int HF_unChkRspdProc(struct sk_buff *skb, struct hfHttpPakCtl *pHfPkCtl, struct http_para * http){
	//DEBUG("HF_unChkRspdProc");
	unsigned int uiRetCode, pakLen;
	
	pakLen = (skb->len-http->htmSPos);
	if(0 == pakLen){
		return HF_OK;
	}
	pHfPkCtl->acuRcvLen += pakLen;

	/*在HF_tlv_exec函数中不再修改pHfPkCtl的数据								*/
	HF_tlv_exec(pHfPkCtl->pRule, pHfPkCtl->uiRulNo);
	/*更新acuSndLen*/
	pHfPkCtl->acuSndLen += (skb->len-http->htmSPos);

	if(pHfPkCtl->acuRcvLen == pHfPkCtl->exptRcvLen){
	/*服务器已发送最后一个帧，此时要在报文尾部填充空格	*/
		DEBUG("1		skb->len:%d		tcpHdLen:%d		ipHdLen:%d		http->len:%d", skb->len, pHFStrMachine->tcpHdLen, pHFStrMachine->ipHdLen, http->len);
		if((((unsigned int)(skb->len-pHFStrMachine->tcpHdLen-pHFStrMachine->ipHdLen))<(skb->len))&&(pHfPkCtl->exptSndLen > pHfPkCtl->acuSndLen)){
			#if 1
			*(pHFStrMachine->skb->data+6) &= 0xBF;
			uiRetCode = nf_nat_mangle_tcp_packet(skb,
												 pHFStrMachine->ct,
												 pHFStrMachine->ctinfo,
												 skb->len-pHFStrMachine->tcpHdLen-pHFStrMachine->ipHdLen, 
												 0,
												 hfSpace,
												 pHfPkCtl->exptSndLen - pHfPkCtl->acuSndLen);
			#endif
			pHfPkCtl->acuSndLen = pHfPkCtl->exptSndLen;	
			DEBUG("HF_unChkRspdProc reach tail clear bit");
		}
		else{
			DEBUG("2ERROR:-------(pHfPkCtl->exptSndLen > pHfPkCtl->acuSndLen)%d-------(skb->len-pHFStrMachine->tcpHdLen-pHFStrMachine->ipHdLen):%d", (pHfPkCtl->exptSndLen - pHfPkCtl->acuSndLen), skb->len-pHFStrMachine->tcpHdLen-pHFStrMachine->ipHdLen);
		}
		clear_bit(HF_DO_STH, &(pHFStrMachine->ct)->status);
	}
	else if(pHfPkCtl->acuRcvLen > pHfPkCtl->exptRcvLen){
		DEBUG("HF_unChkRspdProc is something wrong ? ruleno:%d", pHfPkCtl->uiRulNo);
		#if 0
		return HF_ERROR;
		#else
		clear_bit(HF_DO_STH, &(pHFStrMachine->ct)->status);
		#endif
	}
	return HF_OK;
}
unsigned int HF_adjustCntLen(struct sk_buff *skb, struct http_para *http, struct hfHttpPakCtl *pHfPkCtl){
		unsigned char hfBuf[20];
		int oldLenofL, newLenofL, uiRetCode;
		memset(hfBuf, 0, 20);
		DEBUG("HF_adjustCntLen");

		oldLenofL = http->cntEPos-http->cntSPos;
		pHfPkCtl->exptSndLen += (((unsigned short)(*(pHfPkCtl->pRule+2)))<<8)|((unsigned short)(*(pHfPkCtl->pRule+3)));		
		//将修改后的length写入报文
		sprintf(hfBuf, "%d", pHfPkCtl->exptSndLen);
		newLenofL = strlen(hfBuf);
		if((http->cntSPos < pHFStrMachine->skb->len)&&((oldLenofL+http->cntSPos)< pHFStrMachine->skb->len)){
			if(newLenofL > oldLenofL)
				*(pHFStrMachine->skb->data+6) &= 0xBF;
			uiRetCode = nf_nat_mangle_tcp_packet(skb,
												 pHFStrMachine->ct,
												 pHFStrMachine->ctinfo,
												 http->cntSPos-(pHFStrMachine->http.hdr-pHFStrMachine->skb->data), 
												 oldLenofL,
												 hfBuf,
												 newLenofL);
			http->htmSPos += (newLenofL-oldLenofL);
			DEBUG("HF_adjustCntLen	pHfPkCtl->exptSndLen:%d http->htmSPos:%d", pHfPkCtl->exptSndLen, http->htmSPos);
			return HF_OK;
		}
		return HF_ERROR;
	}

unsigned int HF_getChkSzFromHead(struct sk_buff *skb, struct http_para *http , unsigned int *uiChkSize){
	unsigned int uiRetCode;
	DEBUG("HF_getChkSzFromHead");
	
	http->chkSPos 	= http->htmSPos;
	uiRetCode 		= HF_skb_pos(skb, http->chkSPos, skb->len, "\r\n", 2, &(http->chkEPos));
	if((HF_OK != uiRetCode)||(http->chkEPos <= http->chkSPos)){
		http->cntSPos = 0;
		return HF_ERROR;
	}
	*uiChkSize = 0;
	HF_atoi_hex(skb->data+http->chkSPos, http->chkEPos-http->chkSPos, uiChkSize);
	http->chkHeadNum = 1;
	DEBUG("+++++++++++++++++++++++++++++chkSPos:%d chkEPos:%d uiRetCode:%d", http->chkSPos, http->chkEPos, uiRetCode);
	http->htmSPos += (http->chkEPos-http->chkSPos+2);
	DEBUG("HF_getChkSzFromHead	uiChkSize:%d", *uiChkSize);
	return HF_OK;
}

unsigned int HF_HtmHeadProc(struct sk_buff *skb, struct hfHttpPakCtl *pHfPkCtl, struct http_para * http){
	unsigned int uiRetCode;	
	unsigned char *pValue = pHfPkCtl->pRule;
	unsigned int uiType;

	ASSERT(pValue);
	uiType = (((unsigned short)(*(pValue)))<<8)|((unsigned short)(*(pValue+1)));

	DEBUG("HF_HtmHeadProc");
	if(!ishttprespondhead(http)){
		DEBUG("not httprespondhead\n");
		return HF_ERROR;
	}
	/************************************************************/
	/*如果是重定向TLV，在此执行*/

	if((uiType == HF_L1TLVTYPE_UPDATE)||(uiType == HF_L1TLVTYPE_REDIRECT)||(uiType == HF_L1TLVTYPE_MISREQPROC_REDI)){// 1update 4redirect
		HF_tlv_exec(pValue, pHfPkCtl->uiRulNo);
		return HF_OK;
	}
	/************************************************************/
	uiRetCode = HF_skb_pos(skb, http->hdr-skb->data, skb->len, "\r\n\r\n", 4, &(http->htmSPos));
	if(HF_OK != uiRetCode){
		DEBUG("can't find (http->htmSPos)");
		return HF_ERROR;
	}
	http->htmSPos += 4;
	/************************************************************/
	uiRetCode = HF_getTransType(skb, http, &(pHfPkCtl->isChunked));
	if(HF_SKIP == uiRetCode){
		clear_bit(HF_DO_STH, &(pHFStrMachine->ct)->status);
		DEBUG("+++++SKIP ucRuleNo:%d lnkCtlNo:", pHfPkCtl->uiRulNo);
		return HF_SKIP;
	}
	/************************************************************/
	if(HF_HTTP_CHUNKED == pHfPkCtl->isChunked){
		if(http->htmSPos < skb->len){		
			uiRetCode = HF_getChkSzFromHead(skb, http, &(pHfPkCtl->exptRcvLen));
			DEBUG("pHfPkCtl->exptRcvLen:%d", pHfPkCtl->exptRcvLen);
			if(HF_OK != uiRetCode){
				DEBUG("HF_HtmHeadProc HF_getChkSzFromHead ERR");
				return HF_ERROR;
			}
			/*Add 20140214*/
			if(0 == pHfPkCtl->exptRcvLen){
				clear_bit(HF_DO_STH, &(pHFStrMachine->ct)->status);
				DEBUG("HF_unChkRspdProc reach tail clear bit");
			}
			/*************/
		}
		else
			pHfPkCtl->exptRcvLen = 0;
		pHfPkCtl->exptSndLen = pHfPkCtl->exptRcvLen;
		pHfPkCtl->acuSndLen  = 0;
		pHfPkCtl->acuRcvLen  = 0;
	}
	else if(HF_HTTP_UNCHUNKED == pHfPkCtl->isChunked){
		uiRetCode = HF_getHpCntLen(skb, http, &(pHfPkCtl->exptRcvLen));	
		DEBUG("\npHfPkCtl->exptRcvLen:%d\n", pHfPkCtl->exptRcvLen);
		if(HF_OK != uiRetCode){
			return HF_ERROR;
		}
		pHfPkCtl->exptSndLen = pHfPkCtl->exptRcvLen;
		pHfPkCtl->acuSndLen  = 0;
		pHfPkCtl->acuRcvLen  = 0;
		if(0!=pHfPkCtl->exptRcvLen){
			HF_adjustCntLen(skb, http, pHfPkCtl);
			if(HF_OK != uiRetCode){
				return HF_ERROR;
			}
		}
		else{
			DEBUG("Content-Length:0");
			clear_bit(HF_DO_STH, &(pHFStrMachine->ct)->status);
			DEBUG("HF_unChkRspdProc reach tail clear bit");
			return HF_SKIP;
		}

	}
	else{
		return HF_ERROR;
	}

	return HF_OK;
	/************************************************************/
}
/*进入HF_htprespond_proc函数时,因为添加404处理流程,所以将pRule 等放入*/
unsigned int HF_htprespond_proc_new(unsigned char ucLnkCtlNo, struct sk_buff *skb, struct http_para * http){
	unsigned int uiRetCode;
	struct hfHttpPakCtl *pHfPkCtl = &(hfHtpPakCtl[ucLnkCtlNo]);	

	pHFStrMachine->lendiff = 0;
	if(HF_HTTP_UKNOW == pHfPkCtl->isChunked){
		/*html报文处理前*/
		uiRetCode = HF_HtmHeadProc(skb, pHfPkCtl, http);
		if(HF_SKIP == uiRetCode)
			return HF_OK;
		else if(HF_OK != uiRetCode)
			return HF_ERROR;
	}
	if(HF_HTTP_UNCHUNKED == pHfPkCtl->isChunked)
		uiRetCode = HF_unChkRspdProc(skb, pHfPkCtl, http);
	else if(HF_HTTP_CHUNKED == pHfPkCtl->isChunked)
		uiRetCode = HF_ChkRspdProc(skb, pHfPkCtl, http);
	/*************************************************************/
	/*调整序列号*/
	if(pHFStrMachine->lendiff)
		nf_nat_set_seq_adjust(pHFStrMachine->ct, pHFStrMachine->ctinfo, ((struct tcphdr *)(pHFStrMachine->tcphdr))->seq, pHFStrMachine->lendiff);
	/*************************************************************/
	return uiRetCode;
}

unsigned int HF_skb_linkproc(struct sk_buff *skb, struct http_para *http)
{
	unsigned char ucLnkCtlNo;
	unsigned int uiRetCode;
	pHFStrMachine->skb = skb;
	pHFStrMachine->ct = nf_ct_get(skb, &(pHFStrMachine->ctinfo));
	if(IS_ERR(pHFStrMachine->ct))
		return HF_ERROR;
	pHFStrMachine->lendiff = 0;


	//对所有TCP端口80的报文都要判断是否是HTTP请求,默认LAN中不会架设HTTP服务器。
    if (ishttprequest(http)) 
    {		
		pHFStrMachine->direction = HF_FROM_LAN;
        HF_req_proc_new(skb);
		goto ADJUST_SEQ;
    }

	/*BEGIN Added at 20140217 status:TESTING*/
	if((pHFStrMachine->ctinfo >= IP_CT_IS_REPLY) && ishttprespondhead(http))//如果是http响应头，则进入
	{
		int icount;
		for(icount = 0;icount < pstHFLinkCtl->MisRCtlSize[pstHFLinkCtl->iCurListNo];icount++){
			/*如果命中,选择命中的规则结构体索引,增加pakctl结构*/
			unsigned int ruleno = icount+pstHFLinkCtl->iCurListNo*8;
			if((pstHFLinkCtl->HFMissRegCtl[ruleno].rspTypeVal) 
			&& (0 == (pstHFLinkCtl->HFMissRegCtl[ruleno].aRuleAliveTime[1]))
			&& (0 == memcmp(pstHFLinkCtl->HFMissRegCtl[ruleno].rspTypeVal, http->hdr+9, pstHFLinkCtl->HFMissRegCtl[ruleno].rspTypeLen-1)))
			{
			    pstHFLinkCtl->HFMissRegCtl[ruleno].aRuleAliveTime[1] = pstHFLinkCtl->HFMissRegCtl[ruleno].aRuleAliveTime[0];
				#if 0
				DEBUG("Hit 404 MisRCtlSize:%d rspTypeVal:%s rspTypeLen:%d", pstHFLinkCtl->MisRCtlSize[pstHFLinkCtl->iCurListNo], pstHFLinkCtl->HFMissRegCtl[ruleno].rspTypeVal, pstHFLinkCtl->HFMissRegCtl[ruleno].rspTypeLen-1);
				int icount2;
				DEBUG("-----------------");
				for(icount2 =0;icount2<(pstHFLinkCtl->HFMissRegCtl[ruleno].rspTypeLen-1);icount2++){
					printk("%c", *(http->hdr+9+icount2));
				}
				#endif
				set_bit(HF_DO_STH, &(pHFStrMachine->ct->status));
				/***************************************************************************/
				memset(&(hfHtpPakCtl[pHFStrMachine->nxtHtpCtlNo]), 0, sizeof(struct hfHttpPakCtl));
				hfHtpPakCtl[pHFStrMachine->nxtHtpCtlNo].uiRulNo= ruleno;
				
				hfHtpPakCtl[pHFStrMachine->nxtHtpCtlNo].uiRulType = HF_RUL_40X;
				hfHtpPakCtl[pHFStrMachine->nxtHtpCtlNo].pRule = pstHFLinkCtl->HFMissRegCtl[ruleno].pRule;
				DEBUG("+++++MARK ucRuleNo:%d lnkCtlNo:%d\n", ruleno, pHFStrMachine->nxtHtpCtlNo);
				#if 1
				hfHtpPakCtl[pHFStrMachine->nxtHtpCtlNo].sPort = ntohs(((struct tcphdr *)(pHFStrMachine->tcphdr))->dest);		
				hfHtpPakCtl[pHFStrMachine->nxtHtpCtlNo].sIp4 = *(pHFStrMachine->skb->data+19);		
				hfHtpPakCtl[pHFStrMachine->nxtHtpCtlNo].isChunked = HF_HTTP_UKNOW;
				#endif
				HF_SET_RULENO(pHFStrMachine->ct->status, pHFStrMachine->nxtHtpCtlNo);
				pHFStrMachine->PrcOnBk = 1;
				pHFStrMachine->nxtHtpCtlNo = (pHFStrMachine->nxtHtpCtlNo+1)%HF_HTPPAK_NUM;
				/*404统计信息***********************************************************/
				pstHFLinkCtl->hitNum[icount+HF_RULELIST_SIZE]++;
				/***************************************************************************/
			
				break;
				/***************************************************************************/
			}
		}
	}
	/*END Added at 20140217 status:TESTING*/
	
	//对所有TCP端口80的http响应报文(此处已应用层内容长度大于0判断为http响应)根据标记判断是否需要httpfilter业务处理。
	if (ishttprespond(http) && (pHFStrMachine->ct) &&  test_bit(HF_DO_STH, &(pHFStrMachine->ct)->status) && (pHFStrMachine->ctinfo >= IP_CT_IS_REPLY)){
		ucLnkCtlNo = HF_GET_RULENO((pHFStrMachine->ct)->status);
		/***************************************************************************/
		if((hfHtpPakCtl[ucLnkCtlNo].sPort != ntohs(((struct tcphdr *)(pHFStrMachine->tcphdr))->dest))
		||(hfHtpPakCtl[ucLnkCtlNo].sIp4 != (*(pHFStrMachine->skb->data+19)))){
			DEBUG("++++++++++++++++++++++++++linkctl conflict!");
			DEBUG("%d	%d", ntohs(((struct tcphdr *)(pHFStrMachine->tcphdr))->dest), (*(pHFStrMachine->skb->data+19)));
			clear_bit(HF_DO_STH, &(pHFStrMachine->ct)->status);
			DEBUG("+++++Clear ucRuleNo:%d\n", (pHFStrMachine->ct)->status);
			goto ADJUST_SEQ;
		}
		/***************************************************************************/
			pHFStrMachine->direction = HF_FROM_WAN;
			uiRetCode = HF_htprespond_proc_new(ucLnkCtlNo, skb, http);
			DEBUG("+++++Hit ucRuleNo:%d LnkCtlNo:%d", hfHtpPakCtl[ucLnkCtlNo].uiRulNo, ucLnkCtlNo);
			if(HF_ERROR == uiRetCode){
				DEBUG("HF_htprespond_proc_new ERROR! clear bit DELAYING!  port:%d", hfHtpPakCtl[ucLnkCtlNo].sPort);
				clear_bit(HF_DO_STH, &(pHFStrMachine->ct)->status);
				#ifdef VER_REL
				if(hfHtpPakCtl[ucLnkCtlNo].uiRulType != HF_RUL_40X)
					pstHFLinkCtl->stHFRuleIterm[hfHtpPakCtl[ucLnkCtlNo].uiRulNo].aRuleAliveTime[1] = HF_RULE_DELAYTIME;
				#endif
				goto ADJUST_SEQ;
			}
	}
	


	ADJUST_SEQ:
	if(pHFStrMachine->lendiff){
		nf_nat_set_seq_adjust(pHFStrMachine->ct, pHFStrMachine->ctinfo, ((struct tcphdr *)(pHFStrMachine->tcphdr))->seq, pHFStrMachine->lendiff);
	}
	#ifdef OPENWRT
	#else
		//对所有TCP端口80的报文根据标记判断是否需要调整TCP序列号
    if ((pHFStrMachine->ct)&&  test_bit(IPS_SEQ_ADJUST_BIT, &(pHFStrMachine->ct)->status)) {

        //INFO("Adjust seq needed\n");
        #ifdef OPENWRT
        struct iphdr *iphdr = (struct iphdr *)(skb->data);
        nf_nat_seq_adjust(skb, (pHFStrMachine->ct), pHFStrMachine->ctinfo, iphdr->ihl*4);
        #else
        uiRetCode = nf_nat_seq_adjust(skb, (pHFStrMachine->ct), pHFStrMachine->ctinfo);
		if(1 != uiRetCode){
			DEBUG("++++ERROR! adjust");
		}
        #endif
    }
	#endif
	
   	return HF_OK;
}

/******************************************************************************
function name 	:HF_link_forward 
--------------------------------------------------------------------------------
note		 	: 
--------------------------------------------------------------------------------
auther    		: 
*******************************************************************************/
unsigned int HF_link_forward(unsigned int 				hooknum,
  	      	  					 struct sk_buff 			*skb,
  		  						 const struct net_device 	*in,
  		  						 const struct net_device 	*out,
  		  						 int (*okfn)(struct sk_buff *))
{
    /*http*/
    struct iphdr *iphdr = (struct iphdr *)(skb->data);
    struct tcphdr *tcphdr;
    
    /* check for tcp header */
	if (iphdr->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

    /* check for http header */
    tcphdr = (void *)iphdr + iphdr->ihl*4;
    if (ntohs(tcphdr->source)!= 80
        && ntohs(tcphdr->dest)!= 80)
        return NF_ACCEPT;

	pHFStrMachine->tcphdr = (unsigned char *)tcphdr;		 
	pHFStrMachine->ipHdLen = iphdr->ihl*4;
	pHFStrMachine->tcpHdLen = tcphdr->doff*4;

	memset( &(pHFStrMachine->http),0, sizeof(struct http_para));

    if (ntohs(iphdr->tot_len) > (iphdr->ihl*4 + tcphdr->doff*4))//存在http数据
    {
       	(pHFStrMachine->http).len = ntohs(iphdr->tot_len) - (iphdr->ihl*4 + tcphdr->doff*4);
        (pHFStrMachine->http).hdr = (void *)tcphdr + tcphdr->doff*4;
		(pHFStrMachine->http).htmSPos = (pHFStrMachine->http).hdr-skb->data;
    }else{
		(pHFStrMachine->http).len = 0;
		(pHFStrMachine->http).hdr = NULL;
	}
	if(HF_OK != HF_skb_linkproc(skb, &(pHFStrMachine->http))){
	}
		
	return NF_ACCEPT;
}

/******************************************************************************
function name 	:counters_minus 
--------------------------------------------------------------------------------
note		 	: 
--------------------------------------------------------------------------------
auther    		:  wy
*******************************************************************************/
int counters_minus(int value)
{
	int iCount;
	for(iCount = 0;iCount<(pstHFLinkCtl->aRuleGroupSize[pstHFLinkCtl->iCurListNo]);iCount++){
		if(value < pstHFLinkCtl->stHFRuleIterm[iCount+HF_RULELIST_SIZE*(pstHFLinkCtl->iCurListNo)].aRuleAliveTime[1])
		{
			pstHFLinkCtl->stHFRuleIterm[iCount+HF_RULELIST_SIZE*(pstHFLinkCtl->iCurListNo)].aRuleAliveTime[1] -= value;
		}
		else
		{
			pstHFLinkCtl->stHFRuleIterm[iCount+HF_RULELIST_SIZE*(pstHFLinkCtl->iCurListNo)].aRuleAliveTime[1] = 0;
		}
	}

	for(iCount = 0;iCount<(pstHFLinkCtl->MisRCtlSize[pstHFLinkCtl->iCurListNo]);iCount++){
		if(value < pstHFLinkCtl->HFMissRegCtl[iCount+8*(pstHFLinkCtl->iCurListNo)].aRuleAliveTime[1])
		{
			pstHFLinkCtl->HFMissRegCtl[iCount+8*(pstHFLinkCtl->iCurListNo)].aRuleAliveTime[1] -= value;
		}
		else
		{
			pstHFLinkCtl->HFMissRegCtl[iCount+8*(pstHFLinkCtl->iCurListNo)].aRuleAliveTime[1] = 0;
		}
	}
	
	return 1;
}


/******************************************************************************
function name 	:HF_fix_tcpchecksum 
--------------------------------------------------------------------------------
note		 	: 
--------------------------------------------------------------------------------
auther    		:   wy
*******************************************************************************/
unsigned int HF_fix_tcpchecksum(struct sk_buff *skb)
{
	unsigned 	char 	*skbdata 	= skb->data;		
	struct 		iphdr 	*iph 		= (struct iphdr *)skb->network_header;
	struct 		tcphdr 	*tcph 		= (struct tcphdr *)skb->transport_header;
	unsigned 	int 	tot_len, iph_len;

	//calc the new checksum
	iph 		= ip_hdr(skb);
	tot_len 	= ntohs(iph->tot_len);
	iph_len 	= ip_hdrlen(skb);
	tcph 		= (struct tcphdr *)(skbdata+20);
	tcph->check = 0;
	skb->csum 	= csum_partial((unsigned char *)tcph, tot_len - iph_len,0);
	tcph->check = csum_tcpudp_magic(iph->saddr,
			 						iph->daddr,
			 						ntohs(iph->tot_len) - iph_len,iph->protocol,
			 						skb->csum);

	return 1;
		
}

int HF_hook_init(unsigned int *pHF_hook_func, struct nf_hook_ops *pHF_hook_ops, int hooknum)
{
	pHF_hook_ops->hook=(nf_hookfn *)pHF_hook_func;
	//pHF_hook_ops.owner=THIS_MODULE;
	pHF_hook_ops->pf=PF_INET;
	pHF_hook_ops->hooknum=hooknum;
	pHF_hook_ops->priority=NF_IP_PRI_MANGLE;
	nf_register_hook(pHF_hook_ops);
	return 1;
}

int HF_timer_init(struct timer_list	*pHF_timer_list, 
				  	 void 				*pHF_timer_func, 
				  	 int 				secToWait,
				  	 unsigned long 		data)
{
	init_timer(pHF_timer_list);
	pHF_timer_list->function = pHF_timer_func;
	pHF_timer_list->expires  = jiffies+secToWait*HZ;
	pHF_timer_list->data = data;
	add_timer(pHF_timer_list);
	return 1;
}

static void HF_timer_addwork(unsigned long pwork)
{
	schedule_work((struct work_struct *)pwork);
}


/******************************************************************************
function name 	:HF_init 
--------------------------------------------------------------------------------
note		 	: 
--------------------------------------------------------------------------------
auther    		:   wy
*******************************************************************************/
static int __init HF_init( void )
{
	struct net_device *ndev;
	unsigned int verCheckSumLen;
	interval = 5;
	unsigned int  hfVersionLen;
	unsigned int  idlen;
	
	pstHFLinkCtl = kmalloc(sizeof(struct HFRuleCtl),GFP_KERNEL);
	if(NULL == pstHFLinkCtl){
		return 0;
		DEBUG("kmalloc pstHFLinkCtl error!\n");
	}

	memset(pstHFLinkCtl,0, sizeof(struct HFRuleCtl));
	pstHFRulUpdCtl = kmalloc(sizeof(struct HFRulUpdCtl),GFP_KERNEL);
	if(NULL == pstHFLinkCtl){
		return 0;
		DEBUG("kmalloc pstHFLinkCtl error!\n");
	}

	memset(pstHFRulUpdCtl,0, sizeof(struct HFRulUpdCtl));

	pstHFLinkCtl->iCurListNo = 0;

	memset(pstHFLinkCtl->aRuleGroupSize, 0, 4);

	pstHFRulUpdCtl->HF_flag_server = 1;
	pstHFRulUpdCtl->HF_file_flag	= 0;
	//-------------------hook init-----------------------------
	(void)HF_hook_init((unsigned int *)HF_link_forward, &HF_ops, NF_INET_FORWARD);
	
	//--------------------timer init----------------------------
	HF_timer_init(&HF_tmlist_file, HF_timer_addwork, interval, (unsigned long)(&HF_filework));
	HF_timer_init(&HF_tmlist_rule, HF_timer_addwork, interval, (unsigned long)(&HF_rulework));
	//-------------------------------------------------------
    
	timer_flag1=1;
	timer_flag2=1;

	//---------------------workqueue init----------------------
	INIT_WORK(&HF_filework,HF_file_update);	
	INIT_WORK(&HF_rulework,HF_rule_analyse_new);
	//-------------------------------------------------------

	//----------INIT str machine------------------------------------
	pHFStrMachine = kmalloc(sizeof(struct hFStrMachine) ,GFP_KERNEL);
	memset(pHFStrMachine,0, sizeof(struct hFStrMachine));
	//-------------------------------------------------------
         HF_init_cbc();
	
	ndev = dev_get_by_name(&init_net, "eth2");
	if(NULL != ndev){
		memcpy(pstHFLinkCtl->sysMac, ndev->dev_addr, 6);
		DEBUG("get it");
	}
	if(HF_OK == HF_file_read_L1(HF_CHECKSUM_PATH, pstHFLinkCtl->verCheckSum, HF_MD5_LEN+2, &verCheckSumLen)){
		pstHFLinkCtl->verCheckSum[HF_MD5_LEN+3] = 0;
		DEBUG("verCheckSum:%s verCheckSumLen:%d pstHFLinkCtl->verCheckSum:%02x", pstHFLinkCtl->verCheckSum, verCheckSumLen, pstHFLinkCtl->verCheckSum);
	}

	if(HF_OK == HF_file_read_L1(HF_APPCHECKSUM_PATH, pstHFLinkCtl->appCheckSum, HF_MD5_LEN+2, &verCheckSumLen)){
		pstHFLinkCtl->appCheckSum[HF_MD5_LEN+3] = 0;
		DEBUG("appCheckSum:%s verCheckSumLen:%d pstHFLinkCtl->appCheckSum:%02x", pstHFLinkCtl->appCheckSum, verCheckSumLen, pstHFLinkCtl->appCheckSum);
	}

	if(HF_OK == HF_file_read_L1(HF_VERSION_PATH, pstHFLinkCtl->hfVersion, HF_VERSION_MAXSIZE, &(pstHFLinkCtl->uiLenOfVer))){
		pstHFLinkCtl->hfVersion[HF_VERSION_MAXSIZE-1] = 0;
		DEBUG("hfVersion:%s hfVersionLen:%d pstHFLinkCtl->hfVersion:%d", pstHFLinkCtl->hfVersion, pstHFLinkCtl->uiLenOfVer);
	}
	
	if(HF_OK == HF_file_read_L1(HF_VENDOR_PATH, pstHFLinkCtl->vender_id, HF_VENDORID_MAXSIZE, &(pstHFLinkCtl->uiLenOfVdid))){
		pstHFLinkCtl->vender_id[HF_VENDORID_MAXSIZE-1] = 0;
	}

	get_random_bytes(&(pstHFLinkCtl->randNum), 4);
	//HF_decompress_test();
	DEBUG("\nsysup init succed\n");
	return 0;
}


/******************************************************************************
function name 	:HF_exit 
--------------------------------------------------------------
note		 	: 
--------------------------------------------------------------
auther    		:   wy
*******************************************************************************/
static void __exit HF_exit(void){
	DEBUG("\nGoodbye! \n ");
	nf_unregister_hook(&HF_ops);
	timer_flag1 = 0;
	timer_flag2 = 0;
	del_timer(&HF_tmlist_file);
	del_timer(&HF_tmlist_rule);
	work_clear_pending(&HF_filework);
	work_clear_pending(&HF_rulework);

    if (!IS_ERR(desc.tfm))
    {
	    crypto_free_blkcipher(desc.tfm);
	}

	kfree(pstHFLinkCtl);
	kfree(pstHFRulUpdCtl);

	DEBUG("HF_exit succeed\n");
}

module_init( HF_init);
module_exit( HF_exit);

MODULE_LICENSE( "GPL" );
MODULE_AUTHOR( "MyName" );
