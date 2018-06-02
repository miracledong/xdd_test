#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <netinet/udp.h>
#include "handle_app.h"

#if 0
static int ParseFetionLogin(unsigned char* data,int datalen, struct passenger_info* passenger_info);
static int parse_weixin(unsigned char* data,int datalen, struct passenger_info* passenger_info);
static int ParseWyMailLogin(unsigned char* data,int datalen, struct passenger_info* passenger_info);
static int ParseTaobaoLogin(unsigned char* data,int datalen, struct passenger_info* passenger_info);
static int ParseWeixinImei(unsigned char* data,int datalen, struct passenger_info* passenger_info);
static int parse_weixin_new(char *data,int data_len,struct passenger_info *passenger_info );
static  int parse_mobile_qq_new(unsigned char* data,int datalen, struct passenger_info *passenger_info);
#endif
/* new tcp process */
int  handle_tcp(struct tcphdr *tcphptr, int data_len,struct passenger_info *passenger_info)
{

	unsigned char *data = 0;
	data = (unsigned char *)tcphptr + tcphptr->doff * 4;
	if((tcphptr->dest == htons(8080) || tcphptr->dest == htons(80) || tcphptr->dest == htons(443)) && data_len>20 && data_len == htonl(*(int*)data)
				&& *(int *)(data+4) == htonl(0x100001)&&*(short *)(data+8)==0x0&&(unsigned char)data[16]==0xbf)
	{
		if(parse_weixin_new(data,data_len,passenger_info))				
			return 1;
	}			
	if(( ntohs(tcphptr->source) ==80)||(ntohs(tcphptr->dest) == 80)||( ntohs(tcphptr->source) ==443)||(ntohs(tcphptr->dest) == 443)||( ntohs(tcphptr->source) ==8080)||(ntohs(tcphptr->dest) == 8080)||( ntohs(tcphptr->source) ==14000)||(ntohs(tcphptr->dest) == 14000))
	{										
		if(parse_mobile_qq_new(data,data_len, passenger_info))	
			return 1;	
	}	   
    if(ntohs(tcphptr->dest) >= 8000 && ntohs(tcphptr->dest) <= 9000
        && ParseFetionLogin(data,data_len,passenger_info))
        return 1;
    /*
    	else if(ntohs(tcphptr->dest) >= 8000 && ntohs(tcphptr->dest) <= 9000
        && ParseFetionSend(data,data_len,passenger_info))
        return;
	*/
	if((ntohs(tcphptr->dest) == 8080)||(ntohs(tcphptr->source) == 8080))
	{
        if(ParseWyMailLogin(data,data_len,passenger_info))
        return 1;
	}  
	if((ntohs(tcphptr->dest) == 110)||(ntohs(tcphptr->source) == 110))
	{
        if(ParseSOHUMailLogin(data,data_len,passenger_info))
        return 1;
	}  
         
	else if(ntohs(tcphptr->dest)  == 80
			&& ParseTaobaoLogin(data,data_len,passenger_info))
			return 1;

	
	return 0;
}


int ParseFetionLogin(unsigned char* data,int datalen, struct passenger_info* passenger_info)
{
	if(datalen >50 && data[0] == 0x00 && data[2] == 0x00 && 
		data[3] == 0x15 && data[4] == 0x5 && data[5] == 0x9)
	{
		int  i = 0;
		char FetionName[64] = "";
		datalen = data[1]&0xff;
		for(i = 0;i<datalen-1;i++)
		{
			if(data[i] == 0x1a)
			{	
				i += 1;
				char* strEnd = NULL;
				int j = 0;
				for(j = i;j<datalen-1;j++)
				{
					if(data[j] == 0 || data[j] == 0x3b)
					{
						if(j-i<64)
						{
							memcpy(FetionName,data+i,j-i);
							printf("Fetion Name:%s|\n",FetionName);
							send_virtual_login_data(FetionName, MOBILE_FETION_VIRTUAL_ID, passenger_info );
							return 1;
						}
						break;
					}
				}
				break;
			}
		}
	}
	return 0;
}
#if 0
int ParseFetionSend(unsigned char* data,int datalen, struct virtual_info* passenger_info)
{
	if(datalen >50 && data[2] == 0x00 && data[3] == 0x15 && data[4] == 0x9 && data[5] == 0x6)
	{
		datalen = data[1]&0xff;
		//last data is 0x00
		int i = 0;
		int nBegin = 0;
		//get count begin
		for(i = datalen-2;i>2;i--)
		{
			if(data[i] == 0)
			{
				nBegin = i+1;
				break;
			}
		}

		if(nBegin != 0)
		{
			//get content
			if(datalen-2-nBegin < 8096)
			{
				char content[8096] = "";
				char FetionName[64] = "";
				char opp[64] = "";
				int count = nBegin;
				char temp[5] ="";
				while(count<datalen-1 && data[count]!=0 && strlen(content)<8096)
				{
					memset(temp,0,sizeof(temp));
					if(data[count] >=0x21 && data[count]<=0x7e)
						sprintf(temp,"%c",data[count]);
					else
						sprintf(temp,"%%%x",data[count]);
					strcat(content,temp);
					count++;
				}

				for(i = 0;i<datalen-1;i++)
				{
					if(data[i] == 0x1a)
					{	
						i += 1;
						char* strEnd = NULL;
						int j = 0;
						for(j = i;j<datalen-1;j++)
						{
							if(data[j] == 0 || data[j] == 0x3b)
							{
								if(j-i<64)
								{
									memcpy(FetionName,data+i,j-i);
								}
								break;
							}
						}
						break;
					}
				}
				
				for(i = 0;i<=datalen-1;i++)
				{
					//find sip:
					if(data[i] == 0x3a)
					{	
						char* strEnd = NULL;
						if(strEnd = strstr(data+i+1,"@"))
						{
							int nLen = 0;
							char* strBegin = data+i+1;
							if((nLen = strEnd-strBegin) < 64)
								memcpy(opp,data+i+1,nLen);
						}
						break;
					}
				}

				if(content)
				{
					urldecode(content,strlen(content));
					printf("Fetion Send To:%s Content:%s\n",opp,content);

					struct chat_s *chat_data=NULL;
					chat_data=malloc(sizeof(struct chat_s));
					if(chat_data==NULL){
						return 0;
						}
					memset(chat_data, 0, sizeof(struct chat_s));
					make_chat_data(chat_data, passenger_info);

					chat_data->event_type=my_str_replace(chat_data->event_type,"2");
                    chat_data->chat_type=my_str_replace(chat_data->chat_type,MOBILE_FETION_VIRTUAL_ID);
					chat_data->username=my_str_replace(chat_data->username,FetionName);
					chat_data->opp_username=my_str_replace(chat_data->opp_username,opp);
					chat_data->content=my_str_replace(chat_data->content,content);
			
					//send_chat_data(chat_data);
					return 1;
				}
			}
		}
	}
	return 0;
}
#endif
int parse_weixin(unsigned char* data,int datalen, struct passenger_info* passenger_info)
{
	if(data[0] == 0x00 && data[1] == 0x00 && data[7] == 0x01 && data[8] == 0x3b &&
	   data[9] == 0x9a && data[10] == 0xca && data[11] == 0xb2 && data[18] == 0x00 && 
	   data[19] == 0x00 && data[20] == 0x00 && data[21] == 0x00)
	{
		char qqNum[32] = {'\0'};
		unsigned int QQNum;
		QQNum = (data[22] & 0xff);
		QQNum = (QQNum << 8) + (data[23]&0xff);
		QQNum = (QQNum << 8) + (data[24]&0xff);
        QQNum = (QQNum << 8) + (data[25]&0xff);

		sprintf(qqNum, "%u", QQNum);

		if(strlen(qqNum) > 5)
		{
			//printf("weixin:%s\n",qqNum);
			send_virtual_login_data(qqNum, MOBILE_WEIXIN_VIRTUAL_ID, passenger_info );
			return 1;
		}
	}
	
	return 0;
}


int ParseWyMailLogin(unsigned char* data,int datalen, struct passenger_info* passenger_info)
{
	char szName[256] = {'\0'};
	 if(datalen >30 && data[0] == 0xd1 && data[1] == 0x10 && data[6] == 0x01&& data[7] == 0x00&& data[8] == 0x01)
    	{
	    	//printf("222wy datalen=%d  data =%s\n",datalen,data);
    		//get_content_data(data,"\"user\" : \"","\"",szName,sizeof(szName));

			int i = 0;
			int n = 0;
			while(i<datalen)
			{
				if(data[i-6]==0x22&&data[i-5]==0x75&&data[i-4]==0x73&&data[i-3]==0x65&&data[i-2]==0x72&&data[i-1]==0x22&&data[i]==0x3a)
				{
					i=i+2;
					n=0;
					while(n<50)
					{
						if(data[i]==0x22)
						{
							i=datalen;
							break;
						}
						szName[n]=data[i];
						i++;
						n++;			
					}
				}
				if(data[i-6]==0x22&&data[i-5]==0x75&&data[i-4]==0x73&&data[i-3]==0x65&&data[i-2]==0x72&&data[i-1]==0x22&&data[i]==0x20&&data[i+1]==0x3a&&data[i+2]==0x20)
				{
					i=i+4;
					n=0;
					while(n<50)
					{
						if(data[i]==0x22)
						{
							i=datalen;
							break;
						}
						szName[n]=data[i];
						i++;
						n++;			
					}
				}
				i++;
			}
			//printf("strlen(szName)=%d  =%s \n",strlen(szName),szName);
			if((strlen(szName) >=14)&&(strlen(szName) <=27 ))
		    {
		        printf("WYmail:%s\n",szName);
				if (strcasestr(szName, "163.com"))
		        	send_virtual_login_data(szName, MOBILE_163MAIL_VIRTUAL_ID, passenger_info );
				else if (strcasestr(szName, "126.com"))
		        	send_virtual_login_data(szName, MOBILE_126MAIL_VIRTUAL_ID, passenger_info );

				return 1;
		    }
    	}

	 return 0;
}

int ParseSOHUMailLogin(unsigned char* data,int datalen, struct passenger_info * passenger_info)
{
	char szName[256] = {'\0'};
	//printf("sohu datalen=%d  %02x %02x %02x %02x %02x\n",datalen,data[0],data[1],data[2],data[3],data[4]);
	 if(datalen >5 && data[0] == 0x55 && data[1] == 0x53 && data[2] == 0x45&& data[3] == 0x52&& data[4] == 0x20)
    	{
    	
	    	//printf("222wy datalen=%d  data =%s\n",datalen,data);
    		//get_content_data(data,"\"user\" : \"","\"",szName,sizeof(szName));

			int i = 0;
			int n = 0;
			i=i+5;
			n=0;
			while(n<50)
			{
				if(data[i]==0x0d)
					break;
				szName[n]=data[i];
				i++;
				n++;			
			}
    		if(strstr(szName,"@sohu.com")==NULL)
				strcat(szName,"@sohu.com");
			if((strlen(szName) >=13))
		    {
		        //printf("sohumail:%s\n",szName);
		        	send_virtual_login_data(szName, MOBILE_SOHUMAIL_VIRTUAL_ID, passenger_info );

				return 1;
		    }
    	}

	 return 0;
}

int ParseTaobaoLogin(unsigned char* data,int datalen, struct passenger_info* passenger_info)
{
	char szName[64] = {'\0'};
	char szNewName[512] = {'\0'};
	int len  = 0;

	 if(datalen > 70 && data[0] == 0x88 && data[1] == 0x06 && data[4] == 0x01)
    	{
    		len = data[27]&0xff;
    		if (strcasestr(data + 27, "cntaobao") && len >= 5 && len <= 40)
			{
				strncpy(szName, data + 28, len);
				FormatUrlWord(szName, strlen(szName), szNewName, sizeof(szNewName));
				//printf("taobao id urlcode :%s\n",szNewName);
				urldecode(szNewName,strlen(szNewName));
				replace(szNewName,"cntaobao","");
				//printf("taobao id:%s\n",szNewName);
				send_virtual_login_data(szNewName, MOBILE_TAOBAO_VIRTUAL_ID, passenger_info );
				return 1;
			}
    	}

	 return 0;
}

int ParseWeixinImei(unsigned char* data,int datalen, struct passenger_info* passenger_info)
{
	char strImei[64] = {'\0'};
	char strImsi[64] = {'\0'};
	char *strData = NULL;
	int i,iImeiLen = 0, iImsiLen = 0;

	if (datalen < 200) return 0;

	for(i = 0 ;i < datalen; i++)
		if (data[i] == 0x00)
			data[i] = 0xff;

	strData = strstr(data, "Client.CorrectTime");
	if (!strData) return 0;
	
	printf("imei data1:%s\n", strData);

	if (strlen(strData) <= 70)

	printf("imei data2:%s\n", strData);
	strData += strlen("Client.CorrectTime");
	iImeiLen = strlen(strData+13);
	if ( iImeiLen >= 10 && iImeiLen <= 20 )
	{
		strncpy(strImei, strData+13, 15);
		printf("imei:%s\n", strImei);
		send_virtual_login_data(strImei, MOBILE_IMEI_VIRTUAL_ID, passenger_info );

		if (strstr(strData, "|"))
		{
			
			get_content_data(strData, "|", "|", strImsi, sizeof(strImsi));
			printf("imsi:%s\n", strImsi);
			send_virtual_login_data(strImsi, MOBILE_IMSI_VIRTUAL_ID, passenger_info );
		}

		return 1;
	}

	return 0;
}
int parse_weixin_new(char *data,int data_len,struct passenger_info *passenger_info )
{ 
	char szName[16] = "";
	sprintf(szName,"%u",htonl(*(unsigned int*)(data+23)));
	if(strlen(szName)>1){
	//	printf("Mobile weixin:%s\n", szName);
		 send_virtual_login_data(szName,MOBILE_WEIXIN_VIRTUAL_ID,passenger_info);
		 return 1;		   
   }
	return 0;
}
 int parse_mobile_qq_new(unsigned char* data,int datalen, struct passenger_info *passenger_info)
 {
	if (datalen < 80) return 0;
 
	 if ((data[0] == 0x00 && data[1] == 0x00 && data[7] == 0x08 && data[8] == 0x01)
		 || (data[0] == 0x00 && data[1] == 0x00 && data[8] == 0x01))
	 {
		 char qqNum[32] = {'\0'};
		 char *qqNum_ptr = qqNum;
		 int flag = 0;
		 int i = 0;
		 int zero_count = 0;
		 int qqNumLen = 0;
		 for(i=3;!flag && i<datalen;i++){
 
			 if(zero_count == 4){
				 qqNumLen = data[i]-4;
				 i++;
				 while(isdigit(data[i]) &&
						 strlen(qqNum) <= sizeof(qqNum) &&
						 strlen(qqNum) < qqNumLen){
					 *qqNum_ptr++ = data[i++];
					 flag =  1;
				 }
			 }
			 if(data[i] == 0x00){
				 zero_count++;
			 }else{
				 zero_count=0;
			 }
		 }		 
		 if(strlen(qqNum) > 5){
				//printf("Mobile QQ:%s\n", qqNum);
				//snprintf(qq,strlen(qqNum)+1,"%s",qqNum);
				//strcpy(passenger_info->type,MOBILE_QQ_VIRTUAL_ID);		
				//strcpy(passenger_info->netid,qqNum);
				 send_virtual_login_data(qqNum,MOBILE_QQ_VIRTUAL_ID,passenger_info);
				 if(strstr(qqNum,"@qq.com")==NULL)
					strcat(qqNum,"@qq.com");
				  send_virtual_login_data(qqNum,MOBILE_QQMAIL_VIRTUAL_ID,passenger_info);
				return 1;
			}
	 }
 
	 return 0;
 }



