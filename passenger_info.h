#ifndef __PASSENGER_INFO__H
#define __PASSENGER_INFO__H

#define VERSION "13"
#include "time.h"
//#define LOCATION_ID "1303021069"

typedef struct  _virtual_url_list
{
	char *protocol_type;
	char *url;
	char *start_flag;
	char *end_flag;
	char *urldecode_flag;
	char *data_flag;
	char *id_type;
	char *only_url;
}
virtual_url_list;
typedef struct  _virtual_url_id_list
{
	char *protocol_type;
	char *url;
	char *start_flag;
	char *end_flag;
	char *mail_flag;
	char *urldecode_flag;
	char *data_flag;
	char *id_type;
	char *only_url;
}
virtual_url_id_list;

struct server_ip_list
{
	char *ip;
	struct server_ip_list *next;
};

struct login_data_list_s
{
	char *login_data;
	char *next;
};


struct virtual_info
{
	char *id;
	char *id_type;
	char *time;
	char *name;
};

struct panssenger_info
{
	char version[17];//版本号 The version number
	char event_type[5];//数据类型 Data type
	char doc_version[33];//数据交换标准版本号 Dataexchange standard version number
	char auth_type[9];//认证类型 The authentication type
	char auth_account[33];//认证帐号 Certified account
	char ID_type[8];//登录身份类型 Login ID type
	char ID[65];//登录身份帐号 Account login identity
	char id_name[33];//姓名昵称 The name nickname
	char app_company[128];//APP厂商名称 APP name of manufacturer
	char app_name[128];//APP应用名称 APP application name
	char app_version[32];//APP版本号 APP version number
	char app_authcode[128];//APP终端认证码 APP terminal authentication code
	char location_code[15];//场所编码 Place code
	char location_type[3];//场所类型 Place type
	char login_time[20];//终端上线时间 Terminal login time
	char mac[18];//终端设备MAC MAC of terminal equipment
	char lan_ip[33];//内网IP地址 The network IP address
	char source_ip4[33];//源外网IPv4地址 The source IPv4 address of the external network
	char source_ip6[64];//源外网IPv6地址 The source IPv6 address of the external network
	char source_startport4[6];//源外网IPv4起始端口号 IPv4 source network starting port number
	char source_endport4[6];//源外网IPv4结束端口号 IPv4 source network ending port number
	char source_startport6[6];//源外网IPv6起始端口号 IPv6 source network starting port number
	char source_endport6[5];//源外网IPv6结束端口号 IPv6 source network ending port number
	char apid[22];//无线AP编号 WI-FI AP munber
	char apmac[18];//无线AP-MAC地址 WI-FI AP-MAC address
	char longitude[12];//Wi-Fi AP无线基站经度  Wi-Fi wireless base station longitude
	char latitude[12];//Wi-Fi AP无线基站纬度 Wi-Fi wireless base station latitude
	char rssi[9];//场强 Field
	char session_id[65];//会话ID Conversation ID
	char x[9];//X坐标 X coordinate
	char y[9];//Y坐标 Y coordinate
	char imsi[64];//国际移动用户标示号IMSI International mobile subscriber mark IMSI
	char device_id[64];//设备号IMEI Equipment No
	char terminal_system[16];//终端操作系统 Terminal operating system
	char terminal_brand[32];//终端设备品牌 Terminal equipment brand
	char terminal_brandtype[32];//终端设备型号 Terminal equipment type
	char source[3];//安全厂商信息来源号 Terminal equipment type
	char isp_id[4];//网络服务提供商 Terminal equipment type
	char wan_ip[32];//外网IP地址  IP address of the external network
	char source_port[6];//外网IP端口号 IP port number
	char ssid[32];//Wi-Fi APP无线基站信息 Wi-Fi APP wireless base station information
	char associated[32];//关联信息 Related information
	char floor[16];//楼层 Floor
	char login_type[3];//身份登入类型 Log type
	char plastersign[2];//重传记录标识 Repeat identification record
	//char binding_id_group;
	char logout_time[20];//终端下线时间 Terminal login time
	char binding_id_group[1000];
	time_t last_visit_time;
	struct login_data_list_s *login_list;
	//	char *next;//for list,
};


struct checkin_s
{
	char *version;
	char *event_type;
	char *id;
	char *id_type;
	char *name;
	char *room_num;
	char *session_id;
	char *checkin_time;
	char *location_id;
	char *wan_ip;
	char *lan_ip;
	char *mac;
	char *info_source;
	char *checkin_sn;
	char *reserve1;
	char *reserve2;
	char *ethnic_group;
	char *retive_sn;
	char *increased_count;
	char *turnover;
};//data[19]


struct login_s
{
#if 0 	
	char *version;
	char *event_type;
	char *id;
	char *id_type;
	char *name;//mac
	char *card_publisher_id;
	char *session_id;
	char *login_time;
	char *location_id;
	char *wan_ip;
	char *lan_ip;
	char *mac;
	char *info_source;
	char *dst_ip;
	char *room_num;//mac
	char *passwd;//mac
	char *reserve1;
	char *reserve2;
	char *reserve3;
	char *reserve4;
	char *reserve5;
	char *ethnic_group;
	char *retive_sn;
	char *increased_count;
	char *id_login_type;
	char *virtual_name;

	//char *next;
#endif
	//char *name;//mac
	char *version;//版本号 The version number
	char *event_type;//数据类型 Data type
	char *doc_version;//数据交换标准版本号 Dataexchange standard version number
	char *auth_type;//认证类型 The authentication type
	char *auth_account;//认证帐号 Certified account
	char *id_type;//登录身份类型 Login ID type
	char *id;//登录身份帐号 Account login identity
	char *id_name;//姓名昵称 The name nickname
	char *app_company;//APP厂商名称 APP name of manufacturer
	char *app_name;//APP应用名称 APP application name
	char *app_version;//APP版本号 APP version number
	char *app_authcode;//APP终端认证码 APP terminal authentication code
	char *location_code;//场所编码 Place code
	char *location_type;//场所类型 Place type
	char *login_time;//终端上线时间 Terminal login time
	//char *logout_time;//终端下线时间 Terminal login time
	char *mac;//终端设备MAC MAC of terminal equipment
	char *lan_ip;//内网IP地址 The network IP address
	char *source_ip4;//源外网IPv4地址 The source IPv4 address of the external network
	char *source_ip6;//源外网IPv6地址 The source IPv6 address of the external network
	char *source_startport4;//源外网IPv4起始端口号 IPv4 source network starting port number
	char *source_endport4;//源外网IPv4结束端口号 IPv4 source network ending port number
	char *source_startport6;//源外网IPv6起始端口号 IPv6 source network starting port number
	char *source_endport6;//源外网IPv6结束端口号 IPv6 source network ending port number
	char *apid;//无线AP编号 WI-FI AP munber
	char *apmac;//无线AP-MAC地址 WI-FI AP-MAC address
	char *longitude;//Wi-Fi AP无线基站经度  Wi-Fi wireless base station longitude
	char *latitude;//Wi-Fi AP无线基站纬度 Wi-Fi wireless base station latitude
	char *rssi;//场强 Field
	char *session_id;//会话ID Conversation ID
	char *x;//X坐标 X coordinate
	char *y;//Y坐标 Y coordinate
	char *imsi;//国际移动用户标示号IMSI International mobile subscriber mark IMSI
	char *device_id;//设备号IMEI Equipment No
	char *terminal_system;//终端操作系统 Terminal operating system
	char *terminal_brand;//终端设备品牌 Terminal equipment brand
	char *terminal_brandtype;//终端设备型号 Terminal equipment type
	char *source;//安全厂商信息来源号 Terminal equipment type
	char *isp_id;//网络服务提供商 Terminal equipment type
	char *wan_ip;//外网IP地址  IP address of the external network
	char *source_port;//外网IP端口号 IP port number
	char *ssid;//Wi-Fi APP无线基站信息 Wi-Fi APP wireless base station information
	char *associated;//关联信息 Related information
	char *floor;//楼层 Floor
	char *login_type;//身份登入类型 Log type
	char *plastersign;//重传记录标识 Repeat identification record
	//char *name;
};

struct checkout_s
{
	char *version;
	char *event_type;
	char *binding_id_group;
	char *session_id;
	char *checkin_time;
	char *checkout_time;
	char *location_id;
	char *wan_ip;
	char *lan_ip;
	char *mac;	
	char *room_num;
	char *info_source;
	char *reserve1;
	char *reserve2;
	char *ethnic_group;
	char *retive_sn;
	char *increased_count;
};//data[19]


struct logout_s
{
	char *version;//版本号 The version number
	char *event_type;//数据类型 Data type
	char *doc_version;//数据交换标准版本号 Dataexchange standard version number
	char *auth_type;//认证类型 The authentication type
	char *auth_account;//认证帐号 Certified account
	char *id_type;//登录身份类型 Login ID type
	char *id;//登录身份帐号 Account login identity
	char *id_name;//姓名昵称 The name nickname
	char *app_company;//APP厂商名称 APP name of manufacturer
	char *app_name;//APP应用名称 APP application name
	char *app_version;//APP版本号 APP version number
	char *app_authcode;//APP终端认证码 APP terminal authentication code
	char *location_code;//场所编码 Place code
	char *location_type;//场所类型 Place type
	char *login_time;//终端上线时间 Terminal login time
	char *logout_time;//终端下线时间 Terminal login time
	char *mac;//终端设备MAC MAC of terminal equipment
	char *lan_ip;//内网IP地址 The network IP address
	char *source_ip4;//源外网IPv4地址 The source IPv4 address of the external network
	char *source_ip6;//源外网IPv6地址 The source IPv6 address of the external network
	char *source_startport4;//源外网IPv4起始端口号 IPv4 source network starting port number
	char *source_endport4;//源外网IPv4结束端口号 IPv4 source network ending port number
	char *source_startport6;//源外网IPv6起始端口号 IPv6 source network starting port number
	char *source_endport6;//源外网IPv6结束端口号 IPv6 source network ending port number
	char *apid;//无线AP编号 WI-FI AP munber
	char *apmac;//无线AP-MAC地址 WI-FI AP-MAC address
	char *longitude;//Wi-Fi AP无线基站经度  Wi-Fi wireless base station longitude
	char *latitude;//Wi-Fi AP无线基站纬度 Wi-Fi wireless base station latitude
	char *rssi;//场强 Field
	char *session_id;//会话ID Conversation ID
	char *x;//X坐标 X coordinate
	char *y;//Y坐标 Y coordinate
	char *imsi;//国际移动用户标示号IMSI International mobile subscriber mark IMSI
	char *device_id;//设备号IMEI Equipment No
	char *terminal_system;//终端操作系统 Terminal operating system
	char *terminal_brand;//终端设备品牌 Terminal equipment brand
	char *terminal_brandtype;//终端设备型号 Terminal equipment type
	char *source;//安全厂商信息来源号 Terminal equipment type
	char *isp_id;//网络服务提供商 Terminal equipment type
	char *wan_ip;//外网IP地址  IP address of the external network
	char *source_port;//外网IP端口号 IP port number
	char *ssid;//Wi-Fi APP无线基站信息 Wi-Fi APP wireless base station information
	char *associated;//关联信息 Related information
	char *floor;//楼层 Floor
	char *login_type;//身份登入类型 Log type
	char *plastersign;//重传记录标识 Repeat identification record
	char *binding_id_group;
	//char *name;
};
struct file_log_s
{
	char *version;
	char *event_type;
	char *doc_version;
	char *log_time;
	char *session_id;
	char *netserver_type;
	char *lan_ip;
	char *lan_port;
	char *source_ip4;
	char *source_ip6;
	char *source_startport4;
	char *source_endport4;
	char *source_startport6;	
	char *source_endport6;
	char *destination_ip4;
	char *destination_ip6;
	char *destination_port4;
	char *destination_port6;
	char *mac;
	char *location_code;
	char *apid;
	char *longitude;
	char *latitude;
	char *ap_mac;
	char *source;//安全厂商信息来源号 Terminal equipment type
	char *plastersign;//重传记录标识 Repeat identification record
#if 0
	char *url;
	char *contenttype;
	char *host;
#endif
};

struct url_post_s
{

	char *version;
	char *event_type;
	char *doc_version;
	char *log_time;
	char *session_id;
	char *netserver_type;
	char *lan_ip;
	char *lan_port;
	char *source_ip4;
	char *source_ip6;
	char *source_startport4;
	char *source_endport4;
	char *source_startport6;
	char *source_endport6;
	char *destination_ip4;
	char *destination_ip6;
	char *destination_port4;
	char *destination_port6;
	char *mac;
	char *location_code;
	char *apid;
	char *longitude;
	char *latitude;
	char *apmac;
	char *source;
	char *plastersign;
#if 0
	char *version;
	char *event_type;
	char *proto_type;
	char *url;
	char *posBody;
	char *info3;
	char *ID;
	char *ID_type;
	char *name;	
	char *session_id;
	char *start_time;
	char *location_id;
	char *wan_ip;
	char *lan_ip;
	char *mac;	
	char *info_source;
	char *reserve1;
	char *reserve2;
#endif
};

struct email_s
{
	char *version;
	char *event_type;
	char *email_type;
	char *url;
	char *action;
	char *content;
	char *title;
	char *ID;
	char *ID_type;
	char *name;	
	char *session_id;
	char *start_time;
	char *location_id;
	char *wan_ip;
	char *lan_ip;
	char *mac;	
	char *info_source;
	char *reserve;
	char *room_num;
	char *attachment;
	char *from;
	char *to;
	char *cc;
	char *reserve1;
	char *reserve2;
	char *mail_sn;
	char *reserve3;
	char *reserve4;
	char *reserve5;
	char *powang;
	char *bcc;
};


struct bbs_s
{
	char *version;
	char *event_type;
	char *bbs_type;
	char *url;
	char *action;
	char *content;
	char *title;
	char *ID;
	char *ID_type;
	char *name;	
	char *session_id;
	char *start_time;
	char *location_id;
	char *wan_ip;
	char *lan_ip;
	char *mac;	
	char *info_source;
	char *reserve1;
	char *reserve2;

	char *from;
	char *to;
	char *cc;
	char *bbs_id;
	char *bbs_name;
};

struct weibo_s
{
	char *version;
	char *event_type;
	char *weibo_type;
	char *url;
	char *action;
	char *content;
	char *virtal_ID;
	char *virtal_name;
	char *ID;
	char *ID_type;
	char *name;	
	char *session_id;
	char *start_time;
	char *location_id;
	char *wan_ip;
	char *lan_ip;
	char *mac;	
	char *info_source;
	char *room_num;
};

struct chat_s
{
	char *version;
	char *event_type;
	char *username;
	char *chat_type;
	char *nickname;
	char *opp_username;
	char *opp_nickname;
	char *session_id;
	char *content;
	char *start_time;
	char *location_id;	
	char *wan_ip;
	char *lan_ip;
	char *mac;
	char *info_source;
	char *reserve1;
	char *reserve2;
	char *reserve3;
	char *reserve4;
	char *id;
	char *id_type;
	char *name;
	char *dst_ip;
};
//WKY new data
struct group_s
{
	char *version;
	char *event_type;
	char *username;
	char *chat_type;
	char *nickname;
	char *opp_username;
	char *opp_nickname;
	char *group_id;
	char *group_name;
	char *session_id;
	char *content;
	char *start_time;
	char *location_id;	
	char *wan_ip;
	char *lan_ip;
	char *mac;
	char *info_source;
	char *reserve1;
	char *reserve2;
	char *reserve3;
	char *reserve4;
	char *id;
	char *id_type;
	char *name;
};
struct must_sned_s
{
	char *version;//0
	char *event_type;// 1
	char *id;// 2
	char *id_type;
	char *name;
	char *card_source_sn;
	char *session_id;
	char *checkin_time;
	char *location_id;
	char *wan_ip;
	char *lan_ip;
	char *mac;
	char *info_source;
	char *dst_ip;
	char *room_no;
	char *password;
	char *reserve1;
	char *reserve2;
	char *reserve3;
	char *reserve4;
	char *reserve5;
	char *ethnic_group;
	char *retive_sn;
	char *increased_count;
};


struct delay_true_info
{
	char id[64];
	char id_type[32];
	struct panssenger_info *passenger_tmp;
};


#define MOBILE_QQ_VIRTUAL_ID "1001"
#define	MOBILE_QZONE_VIRTUAL_ID "1063"
#define	MOBILE_TIEBA_VIRTUAL_ID "1057"
#define	MOBILE_MOP_VIRTUAL_ID "1035"
#define	MOBILE_SJJY_VIRTUAL_ID "1218"


#define	MOBILE_ZHIFUBAO_VIRTUAL_ID "7182"



#define	MOBILE_TIANYA_VIRTUAL_ID "1034"
#define	MOBILE_SOHUWEIBO_VIRTUAL_ID "3009"
#define	MOBILE_ZHE800_VIRTUAL_ID "7309"
#define	MOBILE_QQMAIL_VIRTUAL_ID "1065"
#define	MOBILE_163MAIL_VIRTUAL_ID "1009"
#define	MOBILE_126MAIL_VIRTUAL_ID "1013"
#define	MOBILE_QQMAIL_VIRTUAL_ID "1065"
#define	MOBILE_TWEIBO_VIRTUAL_ID "2139"
#define	MOBILE_WEIBO_VIRTUAL_ID "2141"

#define	MOBILE_FETION_VIRTUAL_ID "1054"
#define	MOBILE_BILIN_VIRTUAL_ID "7332"

#define	MOBILE_SOHUMAIL_VIRTUAL_ID "1012"
#define	MOBILE_SINAMAIL_VIRTUAL_ID "1011"
#define	MOBILE_189MAIL_VIRTUAL_ID "1265"
#define	MOBILE_139MAIL_VIRTUAL_ID "1262"
#define	MOBILE_WOMAIL_VIRTUAL_ID "1266"

#define	MOBILE_SEARCHBAIDU_VIRTUAL_ID "2002"
#define	MOBILE_SEARCH360_VIRTUAL_ID "7017"
#define	MOBILE_SEARCHSOGOU_VIRTUAL_ID "7016"
#define	MOBILE_SEARCHBING_VIRTUAL_ID "7018"

#define	MOBILE_163WEIBO_VIRTUAL_ID "7364"

#define	MOBILE_IMEI_VIRTUAL_ID "7298"
#define	MOBILE_IMSI_VIRTUAL_ID "7365"

#define	MOBILE_163BLOG_VIRTUAL_ID "1110"
#define	MOBILE_SINABLOG_VIRTUAL_ID "1109"
#define	MOBILE_SOHUBLOG_VIRTUAL_ID "1107"

#define	DZWWW_VIRTUAL_ID "2211"
#define	QILU_VIRTUAL_ID "7177"



#define	YY_VIRTUAL_ID "1095"
#define	MOBILE_WEIXIN_VIRTUAL_ID "7021"
#define	MOBILE_MILIAO_VIRTUAL_ID "7285"
#define	MOBILE_VIPSHOP_VIRTUAL_ID "7286"
#define	MOBILE_VIP_VIRTUAL_ID "1287"
#define MOBILE_12306_VIRUTAL_ID "7127"
#define MOBILE_TAOBAO_VIRTUAL_ID "1016"



//IM:
#define MOBILE_TALKBOX_VIRTUAL_ID "7366" 	    //talkbox
#define	ALIWANGWANG_VIRTUAL_ID "7299"			//????????
#define MOBILE_QQGROUP_VIRTUAL_ID "1001"		//QQ Group
#define	MOBILE_QQCHAT_VIRTUAL_ID  "1001"		//QQ Chat
#define MOBILE_KAKAO_VIRTUAL_ID   "9005"		//kakao talk

//SNS:
#define MOBILE_KAIXIN_VIRTUAL_ID "1060" 	    //????
#define	MOBILE_RENREN_VIRTUAL_ID "1219" 	    //????
#define	MOBILE_ZHENAI_VIRTUAL_ID "1221" 	    //?ä°®

//TRAVEL:
#define	MOBILE_CTRIP_VIRTUAL_ID "1201"  	    //Ð¯??
#define	MOBILE_HUAZHU_VIRTUAL_ID "7367" 	    //??×¡
#define	MOBILE_RUJIA_VIRTUAL_ID "7368"  	    //????
#define	MOBILE_ELONG_VIRTUAL_ID "1213"  	    //????
#define	MOBILE_BAIDUTRAVEL_VIRTUAL_ID "7307"    //?Ù¶?????
#define	MOBILE_LVMAMA_VIRTUAL_ID "1232"			//Â¿????
#define	MOBILE_MAFENGWO_VIRTUAL_ID "1213"  	    //??????
#define	MOBILE_7TIAN_VIRTUAL_ID "1247"			//7????????
#define	MOBILE_TUNIU_VIRTUAL_ID "1226"  	    //Í¾Å£??????
#define	MOBILE_QUNAR_VIRTUAL_ID "1216"  	    //È¥?Ä¶?
#define	MOBILE_58_VIRTUAL_ID "3044"  	    //È¥?Ä¶?

//SHOPING:
#define	MOBILE_TAOBAO_VIRTUAL_ID "1016" 	    //?Ô±?
#define MOBILE_TMALL_VIRTUAL_ID "7310"          //??Ã¨
#define	MOBILE_JD_VIRTUAL_ID "1154"     	    //????
#define	MOBILE_PAIPAI_VIRTUAL_ID "1287"			//????
#define	MOBILE_DANGDANG_VIRTUAL_ID "1155"  	    //????
#define	MOBILE_GANJI_VIRTUAL_ID "2212"			//?Ï¼?
#define	MOBILE_MEITUAN_VIRTUAL_ID "7313"  	    //????
#define	MOBILE_NUOMI_VIRTUAL_ID "9909"  	    //Å´??
#define	MOBILE_YHD_VIRTUAL_ID "1293"			//Ò»?Åµ?

//BBS:
#define MOBILE_XICI_VIRTUAL_ID "1061"//"9909"     		//??????Í¬
#define	MOBILE_DIANPING_VIRTUAL_ID "1219"//"9910" 		//????
#define	MOBILE_FENGHUANGBBS_VIRTUAL_ID "9911"   //????????
#define	MOBILE_TIEXUE_VIRTUAL_ID "3014"//"9912"    		//??Ñª
#define	MOBILE_DOUBAN_VIRTUAL_ID "3001"//"9913"    		//????
#define	MOBILE_AUTOHOME_VIRTUAL_ID "1176"//"9914"       //????Ö®??
#define MOBILE_c2000_VIRTUAL_ID "7378"          //c2000??Ì³
#define MOBILE_TTX_VIRTUAL_ID "7379"            //????????Ì³
#define MOBILE_XINSS_VIRTUAL_ID "7380"          //????Ë®??Ì³
#define MOBILE_SHUNDEREN_VIRTUAL_ID "7381"      //Ë³????bbs
#define MOBILE_GAOMING_VIRTUAL_ID "7382"        //??????Ì³
#define MOBILE_XIZI_VIRTUAL_ID "7383"           //???Óº?????Ì³
#define MOBILE_EJINGWANG_VIRTUAL_ID "7384"      //e ??????Ì³
#define MOBILE_PENGCHENG_VIRTUAL_ID "7385"      //??????????Ì³
#define MOBILE_WANYI_VIRTUAL_ID "7386"          //Ý¸??????Ì³
#define	MOBILE_KDNET_VIRTUAL_ID "1037"			//????????1
#define	MOBILE_PEOPLE_VIRTUAL_ID "4012"			//Ç¿????Ì³1
#define	MOBILE_163BBS_VIRTUAL_ID "1068"         //??????Ì³
#define	MOBILE_DAYOO_VIRTUAL_ID "7393"			//??????Ì³1
#define	MOBILE_TENCENTBBS_VIRTUAL_ID "2201"	    //??Ñ¶??Ì³1
#define	MOBILE_SOHUBBS_VIRTUAL_ID "2205"	    //?Ñº???Ì³1
#define	MOBILE_SINABBS_VIRTUAL_ID "2204"	    //??????Ì³1
#define	MOBILE_IFENGBBS_VIRTUAL_ID "3013"	    //??????Ì³1

//NEWS:
#define MOBILE_TENCENTNEWS_VIRTUAL_ID "9999"    //??Ñ¸????
#define MOBILE_163NEWS_VIRTUAL_ID "9999"        //????????
#define MOBILE_SINANEWS_VIRTUAL_ID "9999"       //????????
#define MOBILE_IFENGNEWS_VIRTUAL_ID "9999"      //????????

//FRIEND:
#define MOBILE_JIAYUAN_VIRTUAL_ID "9915"        //?À¼Í¼?Ôµ
#define	MOBILE_PENGYOU_VIRTUAL_ID "1173"		//??????

//MISC:
#define MOBILE_VPN_VIRTUAL_ID	  "9004"		//VPN
#define MOBILE_TBRECV_VIRTUAL_ID  "9001"	    //·¢¼þÈË
#define MOBILE_TBADDR_VIRTUAL_ID  "9003"	    //·¢¼þÈË
#define MOBILE_TBPHONE_VIRTUAL_ID  "9006"	    //·¢¼þÈË

//WKY
#define MOBILE_CY_VIRTUAL_ID "1501"
#define MOBILE_QQDUIZHAN_VIRTUAL_ID "3036"
#define MOBILE_YIXIN_VIRTUAL_ID "7324"
#define MOBILE_BAIDUYUN_VIRTUAL_ID "7293"
#define MOBILE_115YUN_VIRTUAL_ID "7296"
#define MOBILE_SUING_VIRTUAL_ID "9202"
#define MOBILE_DIDITACHE_VIRTUAL_ID "9203"
#define MOBILE_MOMO_VIRTUAL_ID "7189"

#define	MOBILE_KUAIDI_VIRTUAL_ID "7412"  	    //È¥?Ä¶?
#define MOBILE_UBER_VIRTUAL_ID "7413" 
#define MOBILE_12306_VIRTUAL_ID "7417" 
#endif


