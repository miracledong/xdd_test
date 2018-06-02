
#define _GNU_SOURCE
#include "handle_app.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <locale.h>
#include "passenger_info.h"
//#include "communicate.h"
#include "decrypt.h"

extern virtual_url_id_list *virtual_get_list;
extern int virtual_get_num;
extern virtual_url_id_list *virtual_post_list;
extern int virtual_post_num;
extern virtual_url_list *IMEI_IMSI_post_list;
extern int IMEI_IMSI_post_num;
extern virtual_url_list *IMEI_IMSI_get_list;
extern int IMEI_IMSI_get_num;
void get_jingdong_login(char* data,struct panssenger_info* passenger_info)
{
	char JdAccount[64] = {'\0'};
	get_content_data(data, "pin=", ";", JdAccount, sizeof(JdAccount));        
	if(strlen(JdAccount) > 3)
	{
		replace(JdAccount,"_p"," ");
//		printf("==============JD:%s================\n",JdAccount);
		send_virtual_login_data(JdAccount, MOBILE_JD_VIRTUAL_ID, passenger_info );
		return 1;
	}
	return 0;
}

void get_xiecheng_login(char *data,struct passenger_info *passenger_info)
{
	char login_name[40] = "";
	get_content_data(data,"UID\" : \"","\"",login_name,sizeof(login_name));
	if(!strlen(login_name))
		get_content_data(data,"UID\":\"","\"",login_name,sizeof(login_name));
	if(strlen(login_name) > 3)
	{
		//printf("==============xiecheng:%s================\n",login_name);
		send_virtual_login_data(login_name, MOBILE_CTRIP_VIRTUAL_ID, passenger_info );
	}
	return;
}

void get_ganji_login(char *data,struct passenger_info *passenger_info)
{
	char login_name[40] = "";
	get_content_data(data,"loginId=","&",login_name,sizeof(login_name));
	if(!strlen(login_name))
		get_content_data(data,"user_id\":\"","\"",login_name,sizeof(login_name));
	if(strlen(login_name) > 3)
	{
		//printf("==============ganji:%s================\n",login_name);
		send_virtual_login_data(login_name, MOBILE_GANJI_VIRTUAL_ID, passenger_info );
	}
	return;
}

void get_tmall_login(char *data,struct passenger_info *passenger_info)
{
	urldecode(data,strlen(data));
//	printf("%s\n",data)	;
	char login_name[40] = "";
	get_content_data(data,"_w_tb_nick=",";",login_name,sizeof(login_name));
	if(!strlen(login_name))
		get_content_data(data,"_nk_=",";",login_name,sizeof(login_name));
	if(!strlen(login_name))
		get_content_data(data,"tracknick",";",login_name,sizeof(login_name));
	if(strlen(login_name) > 3)
	{
		unicode_urldecode(login_name,strlen(login_name));
		//printf("==============tmall:%s================\n",login_name);
		send_virtual_login_data(login_name, MOBILE_TMALL_VIRTUAL_ID, passenger_info );
	}
	return;
}

void get_tmall_login_android(char *data,struct passenger_info *passenger_info)
{
	urldecode(data,strlen(data));
	char login_name[40] = "";
	get_content_data(data,"userId="," ",login_name,sizeof(login_name));
	if(!strlen(login_name))
		get_content_data(data,"loginId=","&",login_name,sizeof(login_name));
	
	if(strlen(login_name) > 3)
	{
		replace(login_name,"cntaobao"," ");
		//printf("==============tmall:%s================\n",login_name);
		send_virtual_login_data(login_name, MOBILE_TMALL_VIRTUAL_ID, passenger_info );
	}
	return;
}


void get_taobao_login(char *data,struct passenger_info *passenger_info)
{
	urldecode(data,strlen(data));
	char taobaoname[64] = "";
	get_content_data(data, "cntaobao", "&", taobaoname, sizeof(taobaoname));        
	if(!strlen(taobaoname))
		get_content_data(data, "_w_tb_nick=", ";", taobaoname, sizeof(taobaoname));        
	if(strlen(taobaoname) > 3)
	{
	//	printf("==============taobao id:%s================\n",taobaoname);
		send_virtual_login_data(taobaoname, MOBILE_TAOBAO_VIRTUAL_ID, passenger_info );
	}
	return;
}

void get_sina_mail_login(char* data,struct panssenger_info* passenger_info)
{
	char JdAccount[64] = {'\0'};
	get_content_data(data, "client_id=", "&", JdAccount, sizeof(JdAccount));        
	if(strlen(JdAccount) > 3)
	{
		//printf("==============sina_mail:%s================\n",JdAccount);
 	
	send_virtual_login_data(JdAccount,MOBILE_SINAMAIL_VIRTUAL_ID , passenger_info );
		return 1;
	}
	return 0;
}

void get_qq_mail_login(char* data,struct panssenger_info* passenger_info)
{
//	printf("%s\n",data);
	char JdAccount[64] = {'\0'};
	get_content_data(data, "qm_ssum=", "&", JdAccount, sizeof(JdAccount));        
	if(!strlen(JdAccount))
		get_content_data(data, "qm_sk=", "&", JdAccount, sizeof(JdAccount));        
	if(!strlen(JdAccount))
		get_content_data(data, "qm_username=", ";", JdAccount, sizeof(JdAccount));        
	if(!strlen(JdAccount))
		get_content_data(data, "qqmail_alias=", ";", JdAccount, sizeof(JdAccount));        
	if(!strlen(JdAccount))
		get_content_data(data, "username=", "&", JdAccount, sizeof(JdAccount));        
	if(strlen(JdAccount) > 3)
	{
		//printf("==============qq_mail:%s================\n",JdAccount);
	//	send_virtual_login_data(JdAccount, MOBILE_KUAIDI_VIRTUAL_ID, passenger_info );
        send_virtual_login_data(JdAccount, MOBILE_QQMAIL_VIRTUAL_ID, passenger_info );
		return 1;
	}
	return 0;
}

void get_kuaidi_login(char* data,struct panssenger_info* passenger_info)
{
	char JdAccount[64] = {'\0'};
	get_content_data(data, "\"mob\":\"", "\"", JdAccount, sizeof(JdAccount));        
	if(!strlen(JdAccount))
		get_content_data(data, "\"umob\":\"", "\"", JdAccount, sizeof(JdAccount));        
	if(strlen(JdAccount) > 3)
	{
		replace(JdAccount,"_p"," ");
		//printf("==============kuaidi:%s================\n",JdAccount);
		send_virtual_login_data(JdAccount, MOBILE_KUAIDI_VIRTUAL_ID, passenger_info );
		return 1;
	}
	return 0;
}

void get_58_login(char *data,struct passenger_info *passenger_info)
{
//	printf("%s\n",data);
	char login_name[40] = "";
	char imei[20] = "";
	get_content_data(data,"UN=","&",login_name,sizeof(login_name));
	if(strlen(login_name) > 3)
	{
	//	printf("==============58:%s================\n",login_name);
		send_virtual_login_data(login_name, MOBILE_58_VIRTUAL_ID, passenger_info );
	}
	get_content_data(data,"imei: "," ",imei,sizeof(imei));
	if(strlen(imei) > 3)
		send_virtual_login_data(imei, MOBILE_IMEI_VIRTUAL_ID, passenger_info );
	return;
}

void get_58_login_android(char *data,struct passenger_info *passenger_info)
{
//	printf("%s\n",data);
	char login_name[40] = "";
	get_content_data(data,"userid=","&",login_name,sizeof(login_name));
	if(strlen(login_name))
	{
		//printf("==============58:%s================\n",login_name);
		send_virtual_login_data(login_name, MOBILE_58_VIRTUAL_ID, passenger_info );
	}
	return;
}

void get_didi_login_ios(char* data,struct panssenger_info* passenger_info)
{
	//printf("%s\n",data);
	char userid[64] = "";
	char imei[100] = "";
	memset(userid,0,sizeof(userid));
	get_content_data(data,"phone=","&",userid,sizeof(userid));
	if(!strlen(userid))
		get_content_data(data,"src=","&",userid,sizeof(userid));
	if(strlen(userid) > 3)
	{
		//printf("\n==============dididache userid=%s================\n",userid);
		send_virtual_login_data(userid, MOBILE_DIDITACHE_VIRTUAL_ID, passenger_info );
	}
#if 0
	get_content_data(data,"imei=","&",imei,sizeof(imei));
	if(strlen(imei) >10)
	{
		printf("==============imei:%s================\n",imei);
	//	send_virtual_login_data(imei, MOBILE_IMEI_VIRTUAL_ID, passenger_info );
	}
#endif
	return ;
}

void get_meituan_login(char* data,struct panssenger_info* passenger_info)
{
//	printf("%s\n",data);
	char userid[64] = "";
	memset(userid,0,sizeof(userid));
	get_content_data(data,"userid=","&",userid,sizeof(userid));
	if(strlen(userid) > 3)
	{
		//printf("\n==============meituan userid=%s================\n",userid);
		send_virtual_login_data(userid, MOBILE_MEITUAN_VIRTUAL_ID, passenger_info);
	}
	return ;
}

void get_weixin_login(char* data,int data_len,struct panssenger_info* passenger_info)
{
	char szName[40]="";
	sprintf(szName,"%u",htonl(*(unsigned  int*)(data + 23)));
	if(strlen(szName) > 5)
	{
		send_virtual_login_data(szName, MOBILE_WEIXIN_VIRTUAL_ID, passenger_info);
		return 1;
	}
	else
		return 0;
}
void get_wangxin_login(char* data,struct panssenger_info* passenger_info)
{
	urldecode(data,strlen(data));
//	printf("%s\n",data);
	char szName[64] = {'\0'};
	get_content_data((char*)data,"uid=","&",szName,sizeof(szName));
	if(!strlen(szName))
		get_content_data((char*)data,"user_id=","&",szName,sizeof(szName));
	if(!strlen(szName))
		get_content_data((char*)data,"nick\":\"","\"",szName,sizeof(szName));
	if(!strlen(szName))
		get_content_data((char*)data,"_w_tb_nick=",";",szName,sizeof(szName));
	if(strlen(szName) > 3)
	{
		urldecode(szName,strlen(szName));
		replace(szName,"cntaobao"," ");
		replace(szName,"cnhhupandj"," ");
		replace(szName,"cnhhupan"," ");
	//	printf("==============Wangxin:%s================\n",szName);
		send_virtual_login_data(szName, ALIWANGWANG_VIRTUAL_ID, passenger_info );
		send_virtual_login_data(szName, MOBILE_TAOBAO_VIRTUAL_ID, passenger_info );
		send_virtual_login_data(szName, MOBILE_TMALL_VIRTUAL_ID, passenger_info );
		return ;
	}

	return ;
}
void parse_android_tianya_login_app(char* data,struct panssenger_info* passenger_info)
{
	char szName[64] = {'\0'};
	get_content_data((char*)data,"user=w=","&",szName,sizeof(szName));
	if(strlen(szName) > 3)
	{
		urldecode(szName,strlen(szName));
	//	printf("android tianya:%s\n",szName);
		send_virtual_login_data(szName, MOBILE_TIANYA_VIRTUAL_ID, passenger_info );
		return ;
	}
	return ;
}
void get_tianya_login_android(char* data,struct panssenger_info* passenger_info)
{
	char szName[64] = {'\0'};
	get_content_data((char*)data,"user=w=","&",szName,sizeof(szName));
	if(strlen(szName) > 3)
	{
		urldecode(szName,strlen(szName));
	//	printf("android tianya:%s\n",szName);
		send_virtual_login_data(szName, MOBILE_TIANYA_VIRTUAL_ID, passenger_info );
		return ;
	}
	return ;
}
void parse_android_tweibo_login(char* data,struct panssenger_info* passenger_info)
{
	char szName[64] = {'\0'};
	get_content_data((char*)data,"p_uin=o",";",szName,sizeof(szName));
	if(strlen(szName) > 3)
	{
	//	printf("android tweibo:%s\n",szName);
		send_virtual_login_data(szName, MOBILE_TWEIBO_VIRTUAL_ID, passenger_info );
		return ;
	}
	return;
}	







void parse_android_139mail_login_app(char* data,struct panssenger_info* passenger_info)
{
	char szName[64] = {'\0'};
	get_content_data((char*)data,"<MSISDN>","<",szName,sizeof(szName));
	if(strlen(szName) > 3)
	{
	//	printf("android 139 mail app login:%s\n",szName);
		send_virtual_login_data(szName, MOBILE_139MAIL_VIRTUAL_ID, passenger_info );
		return 1;
	}
}

void parse_android_wymail_login_app(char* data,struct panssenger_info* passenger_info)
{
	if(strlen(data) >= 10)
	{
	//	printf("android wymail login app login:%s\n",data);
		if (strstr(data, "163.com"))
		{
			send_virtual_login_data(data, MOBILE_163MAIL_VIRTUAL_ID, passenger_info );
		}
		else if (strstr(data, "126.com"))
		{
			send_virtual_login_data(data, MOBILE_126MAIL_VIRTUAL_ID, passenger_info );
		}

		return 1;
	}
}
void parse_ios_fetion_login(char* data,struct panssenger_info* passenger_info)
{
	urldecode(data,strlen(data));
	char szName[64] = {'\0'};
	get_content_data((char*)data,"mobile-no=\"","\"",szName,sizeof(szName));
	if(strlen(szName) > 3)
	{
		urldecode(szName,strlen(szName));
	//	printf("ios fetion:%s\n",szName);
		send_virtual_login_data(szName, MOBILE_FETION_VIRTUAL_ID, passenger_info );
		return 1;
	}
	return ;
}


void parse_ios_miliao_login(char* data,struct panssenger_info* passenger_info)
{
	//printf("%s\n",data);
	char szName[64] = {'\0'};
	get_content_data(data,"uuid=","&",szName,sizeof(szName));
	if(strlen(szName) > 0)
	{
		urldecode(szName,strlen(szName));
	//	printf("ios miliao:%s\n",szName);
		send_virtual_login_data(szName, MOBILE_MILIAO_VIRTUAL_ID, passenger_info );
	}
	return ;
}


void parse_ios_tianya_login_app(char* data,struct panssenger_info* passenger_info)
{
	char szName[64] = {'\0'};
	get_content_data((char*)data,"user=w=","&",szName,sizeof(szName));
	if(strlen(szName) > 3)
	{
		urldecode(szName,strlen(szName));
	//	printf("ios tianya:%s\n",szName);
		send_virtual_login_data(szName, MOBILE_TIANYA_VIRTUAL_ID, passenger_info );
		return ;
	}
	return ;
}



void parse_ios_tweibo_login(char* data,struct panssenger_info* passenger_info)
{
	char szName[64] = {'\0'};
	get_content_data((char*)data,"p_uin=0"," ",szName,sizeof(szName));
	if(strlen(szName) > 3)
	{
		//printf("ios tweibo:%s\n",szName);
		send_virtual_login_data(szName, MOBILE_TWEIBO_VIRTUAL_ID, passenger_info );
		return ;
	}
	return;
}	



void parse_ios_sinaweibo_login_app(char* data,struct panssenger_info* passenger_info)
{
	char szName[64] = {'\0'};
	get_content_data((char*)data,"uid=","&",szName,sizeof(szName));
	if(strlen(szName) > 3)
	{
		//printf("ios weibo app login:%s\n",szName);
		send_virtual_login_data(szName, MOBILE_WEIBO_VIRTUAL_ID, passenger_info );
		return 1;
	}
}


void parse_ios_139mail_login_app(char* data,struct panssenger_info* passenger_info)
{
	char szName[64] = {'\0'};
	get_content_data((char*)data,"cellphone=","&",szName,sizeof(szName));
	if(strlen(szName) > 3)
	{
	//	printf("ios 139 mail app login:%s\n",szName);
		send_virtual_login_data(szName, MOBILE_139MAIL_VIRTUAL_ID, passenger_info );
		return 1;
	}
}


void get_wymail_data(char* src,char* start,char* end,char* target,int limit,char *szTmp)
{
	char *pos1=NULL;
	char* pos2=NULL;
	char* ret = NULL;
	pos1 = strcasestr(src,start);
	if(pos1)
	{
		pos1 += strlen(start);
		pos2 = strcasestr(pos1, end);
		ret = pos2;
		if(pos2 == NULL)
			pos2 = strlen(src) + src;
		if(pos2 && (pos2-pos1 < limit))
			memcpy(target, pos1, pos2-pos1);
		else
			memcpy(target, pos1, limit);
	}
	if(ret != NULL){
		ret = pos2 + strlen(end);
		strcpy(szTmp,ret);
	}
	return ;
}

void parse_ios_wymail_login_app(char* data,struct panssenger_info* passenger_info)
{
	char szName[512] = {'\0'};
	char szUser[64] = {'\0'};
	char szTmp[100] = "";
	char szTmp_t[100] = "";
	get_content_data((char*)data,"\"uidList\":[","]",szName,sizeof(szName));
	if(strlen(szName) >= 10)
	{
		//printf("wymail login app login:%s\n",szName);
		get_wymail_data((char*)szName,"\"","\"",szUser,sizeof(szUser),szTmp);
		while(strlen(szUser) != 0)
		{
			if (strstr(szUser, "163.com"))
			{
				//printf("163 wymail login app login one:%s\n",szUser);
				send_virtual_login_data(szUser, MOBILE_163MAIL_VIRTUAL_ID, passenger_info );
			}
			else if (strstr(szUser, "126.com"))
			{
				//printf("126 wymail login app login one:%s\n",szUser);
				send_virtual_login_data(szUser, MOBILE_126MAIL_VIRTUAL_ID, passenger_info );
			}
			strcpy(szTmp_t,szTmp);
			memset(szTmp,0,sizeof(szTmp));
			memset(szUser,0,sizeof(szUser));
			get_wymail_data((char*)szTmp_t,"\"","\"",szUser,sizeof(szUser),szTmp);
		}
		return 1;
	}
}



void parse_ios_vipshop_login_app(char* data,struct panssenger_info* passenger_info)
{
	urldecode(data,strlen(data));
//	printf("%s\n",data);
	char szName[64] = {'\0'};
	get_content_data((char*)data,"login_name=","&",szName,sizeof(szName));
//	get_content_data((char*)data,"vipruid=","&",szName,sizeof(szName));
	if(!strlen(szName))
		get_content_data((char*)data,"userid=","%",szName,sizeof(szName));
	if(!strlen(szName))
		get_content_data((char*)data,"user_id=",";",szName,sizeof(szName));
	if(!strlen(szName))
		get_content_data((char*)data,"vipruid=","&",szName,sizeof(szName));
	if(strlen(szName) > 3)
	{
		if(strstr(szName,"**") || strlen(szName) > 15)
			return;
		//printf("ios vipshop login:%s\n",szName);
	 
		send_virtual_login_data(szName,MOBILE_VIPSHOP_VIRTUAL_ID, passenger_info );
		return 1;
	}
}

char *space_dele(char *taobao)
{
	char exchange[64]={"\0"};
	int i;
	taobao++;
	strcpy(exchange,taobao);
	memset(taobao,0,strlen(taobao));
	strcpy(taobao,exchange);
	return taobao;	

}

int  parse_json_app(char* data,struct panssenger_info* passenger_info, virtual_url_id_list *url_data)
{
    char szName[64] = {'\0'};
	//printf("=======parse_json_app======\n");
	if(strcasestr(url_data->urldecode_flag,"yes"))
		urldecode(data,strlen(data));
	else if(strcasestr(url_data->urldecode_flag,"two"))
	{
		urldecode(data,strlen(data));
		urldecode(data,strlen(data));
	}
	if(strcasestr(url_data->urldecode_flag,"three"))
	{
		urldecode(data,strlen(data));
		urldecode(data,strlen(data));
		urldecode(data,strlen(data));
	}
	
	if(strcasestr(url_data->end_flag,"0x0d"))
	{
		char buf=0x0d;
			get_content_data((char*)data,url_data->start_flag,&buf,szName,sizeof(szName));
	}
	else
   	 	get_content_data((char*)data,url_data->start_flag,url_data->end_flag,szName,sizeof(szName));
    if(strlen(szName) != 0)
    {
    	if(!strcasestr(url_data->mail_flag,"no"))
    	{
    		if(strstr(szName,url_data->mail_flag)==NULL)
				strcat(szName,url_data->mail_flag);
    	}
       // printf("type:%s app login:%s\n",url_data->id_type,szName);
        send_virtual_login_data(szName, url_data->id_type, passenger_info );
		return 1;
	 }
	return 0;
}

int  parse_json_imeiimsi_app(char* data,struct panssenger_info* passenger_info, virtual_url_list *url_data)
{    

	//printf("========json======imeiimsi=============\n");
    char imei[64] = {0};
    char imsi[64] = {0};
	char szName[64] = {'\0'};
	if(strcasestr(url_data->urldecode_flag,"yes"))
	 	urldecode(data,strlen(data));
	if(strcasestr(url_data->end_flag,"0x0d"))
	{
		char buf=0x0d;
		get_content_data((char*)data,url_data->start_flag,&buf,szName,sizeof(szName));
	}
	else
   	 get_content_data((char*)data,url_data->start_flag,url_data->end_flag,szName,sizeof(szName));
	if(strcasestr(url_data->id_type,MOBILE_IMEI_VIRTUAL_ID))
	{
		if(strlen(szName)==IMEI_LEN)
	    {
	        printf("imei:%s\n",szName);
			send_virtual_login_data(szName, url_data->id_type, passenger_info );
			return 1;
		}
	}
	else if(strcasestr(url_data->id_type,MOBILE_IMSI_VIRTUAL_ID)) 
	{
		if((strlen(szName)<=IMSI_LEN_MAX)&&((strlen(szName)>=IMSI_LEN_MIN)))
	    {
	        printf("imsi:%s\n",szName);
			send_virtual_login_data(szName, url_data->id_type, passenger_info );
			return 1;
	    }
	}
	return 0;
}


void handle_app(char* match,struct session_t *session, struct panssenger_info* passenger_info)
{
	int get_num = 0;
	int post_num = 0;

	struct url_s *url_tmp = (struct url_s *)session->url_data;
	char *url = url_tmp->url;
	char *post_data = session->req_data_buf;
	char *res_data = session->rep_data_buf;
	int rlen = session->rep_data_offset;
	int len = session->req_data_offset;
	char *referer= session->referer;
#if 0
	printf("session->request_type %d\n",session->request_type);
	printf("1\n");
	urldecode(url,strlen(url));
	printf("%s\n",url);
	printf("2\n");
	urldecode(session->cookie_buf,strlen(session->cookie_buf));
	printf("%s\n",session->cookie_buf);
	printf("3\n");
	urldecode(post_data,strlen(post_data));
	printf("%s\n",post_data);
	return;
#endif
	if(session->request_type == REQ_TYPE_GET)
	{
#if 1
//		if(strstr(url,"/api/v2/p_checkvipuser") != 0	\
				||(strstr(url,"xiaojukeji.com") != 0 && strstr(url,"risk-pic") != 0)	\
				||(strstr(url,"diditaxi.com.cn") != 0 ))
			//	||(strstr(url,"diditaxi.com.cn") != 0 && strstr(url,"passenger/login") != 0))
		if(strstr(url,"api.udache.com/gulfstream") || strstr(url,".xiaojukeji.com/ep/as/toggles")
				|| strstr(url,"xiaojukeji.com/api/stat/ios") || strstr(url,"mp.xiaojukeji.com/api-mobile-protect/MobileProtect/getConf"))
		{
			get_didi_login_ios(url,passenger_info);
			return 0;
		}
#endif
		else if(strstr(url,"wireless.tianya.cn") && strstr(url,"relation"))
		{
			get_tianya_login_android(session->cookie_buf,passenger_info);
			return 0;
		}
		else if(strstr(url,"dkallot.wangxin.taobao.com/imlogingw/tcp60login") != NULL ||
				strstr(url,"yiliao.hupan.com/api/v2") != NULL )
		{
			get_taobao_login(url,passenger_info);
			return 0;
		}
		
		else if(strstr(url,"api.meituan.com") != 0 && (strstr(url,"/group/v3/abtest") != 0 ||strstr(url,"group/v2/recommend") || strstr(url,"config") != 0))
		{
			get_meituan_login(url,passenger_info);
			return 0;
		}
		else if(strstr(url,"wxapi.taobao.com/api/profile/getUserList"))
			get_wangxin_login(session->cookie_buf,passenger_info);
		else if(strstr(url,"api.m.taobao.com") || (strstr(url,"h5.m.taobao.com") && strstr(url,"hj/app.html")) || (strstr(url,"wangxin.taobao.com") != 0 || strstr(url,"wxapi.taobao.com") != 0)
				&& (strstr(url,"xblink/packages.json") != 0 || strstr(url,"patch") != 0 || strstr(url,"api/user") != 0))
		{
			get_wangxin_login(url,passenger_info);
			get_wangxin_login(session->cookie_buf,passenger_info);
		//	get_wangxin_login(post_data,passenger_info);
			return 0;
		}
		else if(strstr(url,"client.action?functionId") != 0)
		{
			get_jingdong_login(session->cookie_buf,passenger_info);
			return 0;
		}
		else if(strcasestr(url,"/v3.7/user/") != 0	\
				||(strstr(url,"api.chat.xiaomi.net") && strstr(url,"backyard")))
		{	 
			parse_ios_miliao_login(url,passenger_info);
			return ;
		}
		else if(strcasestr(url,"wireless.tianya.cn/v/mobileModule/getModule")) 
		{   
			parse_ios_tianya_login_app(session->cookie_buf, passenger_info);
			return ;
		}
		else if(strcasestr(url,"pushemail.10086.cn/e/resource/login") != 0)
		{	 
			parse_ios_139mail_login_app(url,passenger_info);
			return ;
		}
		else if(strstr(url,"mst.vip.com/uploadfiles"))
		{
			parse_ios_vipshop_login_app(url,passenger_info);
			return;
		}
		else if(strcasestr(url,"appvipshop.com") != 0 && (strstr(url,"vips-mobile-tracker") != 0)
				|| strstr(url,"vips-mobile/router") != 0)
		{	 
			parse_ios_vipshop_login_app(url,passenger_info);
//			parse_ios_vipshop_login_app(session->cookie_buf,passenger_info);
//			parse_ios_vipshop_login_app(post_data,passenger_info);
			return ;
		}
		else if(strcasestr(url,"wireless.tianya.cn/v/q/relation/selectAll")) 
		{   
			parse_android_tianya_login_app(session->cookie_buf, passenger_info);
			return ;
		}
		get_num = 0;
		while(get_num<virtual_get_num)
		{
			//printf("virtual_get_list  json url=%s\n",virtual_post_list[get_num].url);
			//printf("url = %s \n",url);
			if(strstr(url,virtual_get_list[get_num].url))
			{
				memset(passenger_info->ID_type,0,sizeof(passenger_info->ID_type ));
				if(strstr(virtual_get_list[get_num].data_flag,"url"))
				{
					if((parse_json_app(url, passenger_info,&virtual_get_list[get_num])==1)&&(strcmp(virtual_get_list[get_num].only_url,"yes")==0))
						return 1; 
				}
				else if(strstr(virtual_get_list[get_num].data_flag,"cookie_buf")) 
				{
					if((parse_json_app(session->cookie_buf, passenger_info,&virtual_get_list[get_num])==1)&&(strcmp(virtual_get_list[get_num].only_url,"yes")==0))
						return 1; 
				}
				else if(strstr(virtual_get_list[get_num].data_flag,"data_tcp")) 
				{
					if((parse_json_app(match, passenger_info,&virtual_get_list[get_num])==1)&&(strcmp(virtual_get_list[get_num].only_url,"yes")==0))
						return 1; 
				}

			}
			get_num++;
		}
		get_num = 0;
		while(get_num<IMEI_IMSI_get_num)
		{
			if(strstr(url,IMEI_IMSI_get_list[get_num].url))
			{
				memset(passenger_info->ID_type,0,sizeof(passenger_info->ID_type ));
				if(strstr(IMEI_IMSI_get_list[get_num].data_flag,"url"))
				{
					if((parse_json_imeiimsi_app(url, passenger_info,&IMEI_IMSI_get_list[get_num])==1)&&(strcmp(IMEI_IMSI_get_list[get_num].only_url,"yes")==0))
						return 1; 
				}
				else if(strstr(IMEI_IMSI_get_list[get_num].data_flag,"cookie_buf")) 
				{
					if((parse_json_imeiimsi_app(session->cookie_buf, passenger_info,&IMEI_IMSI_get_list[get_num])==1)&&(strcmp(IMEI_IMSI_get_list[get_num].only_url,"yes")==0))
						return 1; 
				}
				else if(strstr(IMEI_IMSI_get_list[get_num].data_flag,"data_tcp")) 
				{
					if((parse_json_imeiimsi_app(match, passenger_info,&IMEI_IMSI_get_list[get_num])==1)&&(strcmp(IMEI_IMSI_get_list[get_num].only_url,"yes")==0))
						return 1; 
				}
			}
			get_num++;
		}
	}
	else if(session->request_type == REQ_TYPE_POST)
	{
		if(strstr(url,"client.action?functionId=") != 0)
		{
			get_jingdong_login(session->cookie_buf,passenger_info);
			return 0;
		}
		else if(strstr(url,"adash.m.taobao.com/rest/ur") != NULL)
		{
			get_taobao_login(session->cookie_buf,passenger_info);
			get_tmall_login(session->cookie_buf,passenger_info);
			return 0;
		}
#if 0
		else if(strcasestr(url,"api.mail.sina.com.cn") && strstr(url,"1/sauth"))
		{
			get_sina_mail_login(post_data,passenger_info);
			return ;
		}
#endif
		else if(strcasestr(url,"mail.qq.com") && strstr(url,"cgi-bin"))
		{
			get_qq_mail_login(session->cookie_buf,passenger_info);
			return ;
		}

		else if(strstr(url,"kuaidadi.com") && (strstr(url,"taxi/a/js.do") != 0
					|| strstr(url,"dfcar/request") != 0))
		{
			get_kuaidi_login(url,passenger_info);
		//	get_kuaidi_login(post_data,passenger_info);
			return 0;
		}
		else if(strstr(url,"m.ctrip.com") != 0 && strstr(url,"restapi") != 0)
		{
			get_xiecheng_login(post_data,passenger_info);
			return 0;
		}
		else if(strstr(url,"app.58.com") != 0 && (strstr(url,"/api/log/api") != 0\
					|| strstr(url,"/api/windex/getHotWords/") \
					|| strstr(url,"/api/push/newgl/index/list")))
		{
			get_58_login(post_data,passenger_info);
			return 0;
		}
		else if(strstr(url,"qy.58.com/getinviteunread"))
		{
			get_58_login_android(post_data,passenger_info);
			return 0;
		}
		else if((strstr(url,"mobds.ganji.cn") != 0 && strstr(url,"datashare") != 0)
				|| (strstr(url,"mobds.ganji.com") != 0 && strstr(url,"common/devices") != 0))
		{
			get_ganji_login(post_data,passenger_info);
			return 0;
		}
		else if((strstr(url,"m.taobao.com") != 0 && strstr(url,"amdc") != 0)
				|| (strstr(url,"hupan.com") != 0 && strstr(url,"api") != 0))
		{
			get_taobao_login(url,passenger_info);
			return 0;
		}
		#if 0
		else if(strcasestr(url,"taobao.com") != 0 && strstr(url,"rest") != 0)
		{	 
			get_tmall_login(session->cookie_buf,passenger_info);
			get_tmall_login(url,passenger_info);
			get_tmall_login(post_data,passenger_info);
			return ;
		}
		
		else if(strcasestr(url,"taobao.com") != 0 && strstr(url,"api/v2/account") != 0)
		{	 
			get_tmall_login_android(post_data,passenger_info);
			get_tmall_login_android(url,passenger_info);
			return ;
		}
#endif
		else if(strcasestr(url,"mnav.fetion.com.cn/mnav/getNetSystemconfig.aspx") != 0)
		{	 
			parse_ios_fetion_login(post_data,passenger_info);
			return ;
		}

		else if(strcasestr(url,"r.t.qq.com") && (strstr(url,"cbdata/vist/config") || strstr(url,"cbdata/Message"))) 
		{   
			parse_ios_tweibo_login(session->cookie_buf,passenger_info);		
			return ;
		}
		else if(strcasestr(url,"wbapp.mobile.sina.cn/wbapplua/wbpullad.lua"))    
		{
			parse_ios_sinaweibo_login_app(post_data, passenger_info);
			return ;
		}
		else if(strcasestr(url,"update.client.163.com/apptrack/AppActivity/aaq.do") != 0
				|| (strstr(url,"client.163.com") != 0 && strstr(url,"apptrack/AppActivity") != 0))
		{	 
			parse_ios_wymail_login_app(post_data,passenger_info);
		//	parse_ios_wymail_login_app(url,passenger_info);
			return ;
		}
		else if(strcasestr(url,"r.t.qq.com/cbdata/user/getFollowList")) 
		{   
			parse_android_tweibo_login(session->cookie_buf,passenger_info);		
			return ;
		}
		else if(strcasestr(url,"ose.caiyun.feixin.10086.cn:80/richlifeApp/devapp/IUser") != 0)
		{	 
			parse_android_139mail_login_app(post_data,passenger_info);
			return ;
		}
		post_num = 0;
		while(post_num<virtual_post_num)
		{
			//printf("virtual_post_list  json url=%s\n",virtual_post_list[post_num].url);
			if(strstr(url,virtual_post_list[post_num].url))
			{
				memset(passenger_info->ID_type,0,sizeof(passenger_info->ID_type ));
				if(strstr(virtual_post_list[post_num].data_flag,"url"))
				{
					if((parse_json_app(url, passenger_info,&virtual_post_list[post_num])==1)&&(strcmp(virtual_post_list[post_num].only_url,"yes")==0))			
						return 1;
				}
				else if(strstr(virtual_post_list[post_num].data_flag,"cookie_buf"))
				{
					if((parse_json_app(session->cookie_buf, passenger_info,&virtual_post_list[post_num])==1)&&(strcmp(virtual_post_list[post_num].only_url,"yes")==0))	
						return 1;
				}
				else if(strstr(virtual_post_list[post_num].data_flag,"post_data"))
				{
				if((parse_json_app(post_data, passenger_info,&virtual_post_list[post_num])==1)&&(strcmp(virtual_post_list[post_num].only_url,"yes")==0))					
						return 1;
				}
				else if(strstr(virtual_post_list[post_num].data_flag,"data_tcp"))
				{
				if((parse_json_app(match, passenger_info,&virtual_post_list[post_num])==1)&&(strcmp(virtual_post_list[post_num].only_url,"yes")==0))					
						return 1;
				}
			}
			post_num++;
		}
		post_num = 0;
		while(post_num<IMEI_IMSI_post_num)
		{	
			//printf("IMEI_IMSI_post_listjson url=%s\n",IMEI_IMSI_post_list[post_num].url);
			if(strstr(url,IMEI_IMSI_post_list[post_num].url))
			{
				memset(passenger_info->ID_type,0,sizeof(passenger_info->ID_type ));
				if(strstr(IMEI_IMSI_post_list[post_num].data_flag,"url"))
				{
					if((parse_json_imeiimsi_app(url, passenger_info,&IMEI_IMSI_post_list[post_num])==1)&&(strcmp(IMEI_IMSI_post_list[post_num].only_url,"yes")==0))	
						return 1;
				}
				else if(strstr(IMEI_IMSI_post_list[post_num].data_flag,"cookie_buf"))
				{
					if((parse_json_imeiimsi_app(session->cookie_buf, passenger_info,&IMEI_IMSI_post_list[post_num])==1)&&(strcmp(IMEI_IMSI_post_list[post_num].only_url,"yes")==0))	
						return 1;
				}
				else if(strstr(IMEI_IMSI_post_list[post_num].data_flag,"post_data"))
				{
					if((parse_json_imeiimsi_app(post_data, passenger_info,&IMEI_IMSI_post_list[post_num])==1)&&(strcmp(IMEI_IMSI_post_list[post_num].only_url,"yes")==0))					
						return 1;
				}
				else if(strstr(IMEI_IMSI_post_list[post_num].data_flag,"data_tcp"))
				{
					if((parse_json_imeiimsi_app(match, passenger_info,&IMEI_IMSI_post_list[post_num])==1)&&(strcmp(IMEI_IMSI_post_list[post_num].only_url,"yes")==0))					
						return 1;
				}
			}
			post_num++;
		}
	}
	return 0;
}
