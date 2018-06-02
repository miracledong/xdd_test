#define _GNU_SOURCE
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <linux/netfilter.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>

#include "sniffer_util.h"
#include "passenger_info.h"

extern network_card[10];

//char br_ifname[32] = {'\0'};


//extern struct server_ip_list *center_ip;




void AEI_get_lan_macaddr(char *addr)
{
	int fd;
	struct ifreq intf;

	if (addr == NULL)
		return;

	if((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("socket error!\n");
		return;
	}

	strcpy(intf.ifr_name, network_card);
	if(ioctl(fd, SIOCGIFHWADDR, &intf) != -1)
	{
		sprintf(addr, "%02x:%02x:%02x:%02x:%02x:%02x",  (unsigned char)intf.ifr_hwaddr.sa_data[0],
								(unsigned char)intf.ifr_hwaddr.sa_data[1],
								(unsigned char)intf.ifr_hwaddr.sa_data[2],
								(unsigned char)intf.ifr_hwaddr.sa_data[3],
								(unsigned char)intf.ifr_hwaddr.sa_data[4],
								(unsigned char)intf.ifr_hwaddr.sa_data[5]);
	}
	close(fd);
	return;

}
int get_content_data(char* src,char* start,char* end,char* target,int limit)
{
	char *pos1=NULL,*pos2=NULL;
	
	pos1=strcasestr(src,start);
	if(pos1){
		pos1+=strlen(start);
		pos2 = strcasestr(pos1, end);
		
		if(pos2==NULL)
			pos2 = strlen(src)+src;
		
		if(pos2&&(pos2-pos1<limit)){
			memcpy(target, pos1, pos2-pos1);
		}
	}
	return 1;
}
#if 0
void getmode()
{
#ifdef NVRAM_BCM
    char *val;
    int len;
    char buff[10]={'\0'};
    val=nvram_get("server_mode");
    if(val!=NULL)
    {
        strcpy(buff,val);
        len=strlen(buff);
        if(buff[len-1]=='\n')  buff[len-1]='\0';
        monitor_mode=atoi(buff);
    }
#else
    int len;
    char buff[10]={'\0'};
    get_config("server_mode",buff);
    monitor_mode=atoi(buff);
#endif
}



void GetLastContent(char* source,char* start,char* end,char* target,int nLen)
{
	if(source == 0 || strlen(source) == 0)
		return;

	char* temp = NULL;
	char* flag = source;
	while((flag = strcasestr(flag,start)) != NULL)
	{
		temp = flag;
		flag += strlen(start);
	}

	if(temp)
	{
		get_content_data(temp,start,end,target,nLen);
	}
}

void dump_center_ip()
{
    struct server_ip_list *temp=center_ip;
    while(temp)
    {
        printf("center_ip:%s\n",temp->ip);
        temp=temp->next;
    }
}
void free_server_ip()
{
    struct server_ip_list *tmp=center_ip;
    struct server_ip_list *next;

    while(tmp)
    {
        next=tmp->next;
        free(tmp->ip);
        tmp->ip = NULL;

        free(tmp);
        tmp = next;
    }
    center_ip = NULL; 
}
void get_server_ip(char *temp)
{
    char *pos=NULL;
    struct server_ip_list *buff=NULL;
    pos=strtok(temp,",");

    while(pos)
    {
        buff=malloc(sizeof(struct server_ip_list));
        buff->ip=malloc(strlen(pos)+1);
		memset(buff->ip,0,strlen(pos)+1);
        strcpy(buff->ip,pos);

		buff->next=center_ip;
		center_ip=buff;
		pos=strtok(NULL,",");
	}

}
#endif
#if 0

char *get_url_path_from_packet(char *data, int datalen, char *url, char* fullpath)
{

	char *httpData = data;
	if(httpData == NULL) return NULL;

	int http_len = datalen;
	if(http_len <= 0)  return NULL;
	char path_tmp[512]="";

	if ((memcmp(httpData, "GET", 3) != 0) && (memcmp(httpData,"POST", 4) != 0))  return NULL;

	char *pFindEnd = strstr(httpData,"\r");
	if (pFindEnd != NULL)
	{
		int tmpLen = (pFindEnd - httpData) - 4 - 9;
		if ( tmpLen <= 0 )  
			return NULL;


		if ( tmpLen >  MAX_URL_LEN)
		{
			tmpLen = MAX_URL_LEN;
		}

		if (memcmp(httpData, "GET", 3) == 0)
			strncpy(path_tmp, httpData+4,tmpLen); 
		else
			strncpy(path_tmp, httpData+5,tmpLen);


		if (!((strcasestr(path_tmp, ".gif" ) != NULL)
					|| (strcasestr(path_tmp, ".jpg") != NULL)
					|| (strcasestr(path_tmp,".JPG") != NULL)
					|| (strcasestr(path_tmp,".css") != NULL)
					|| (strcasestr(path_tmp, ".zip") != NULL)
					|| (strcasestr(path_tmp, ".exe") != NULL)
					|| (strcasestr(path_tmp, ".mp") != NULL)
					|| (strcasestr(path_tmp, ".flv") != NULL)
					|| (strcasestr(path_tmp, ".ico") != NULL)
					|| (strcasestr(path_tmp, ".gz") != NULL)
					|| (strcasestr(path_tmp, ".swf") != NULL)
					|| (strcasestr(path_tmp, ".cgi") != NULL)
					|| (strcasestr(path_tmp,".png") != NULL)))
		{
			char *pHost = strstr(httpData, "Host");
			if(pHost == NULL)  return NULL;

			char *pHostEnd = strstr(pHost, "\r");
			if(pHostEnd != NULL)
			{
				int nHostLen = (pHostEnd - pHost) - 6;
				if((nHostLen <= 0 ) || (nHostLen > 398))  return NULL;

				strncpy(url,pHost+6,nHostLen);
				strncpy(fullpath,pHost+6,nHostLen);
				if(strcmp(path_tmp, "/"))
					strncpy(fullpath+nHostLen,path_tmp,tmpLen);
				if(url[strlen(url)] == '/')
					url[strlen(url)] = '\0';
				if(fullpath[strlen(fullpath)] == '/')
					fullpath[strlen(fullpath)] = '\0';

				return url;
			}
		}

	}

	return NULL;
}
#endif
