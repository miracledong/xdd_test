#include <netinet/ip.h>
#include <signal.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/types.h>
#include <asm/types.h>
#include <features.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <netinet/ether.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>

#include "list.h"
#include "create_sock.h"
#include "passenger_info.h"
#include "sniffer_data.h"
#include "ip_list.h"
#include "send_util.h"
#include "session.h"
#include "cJSON.h"


#define SEND_BUFF_SIZE 8192
#define BUFSIZE 2048
#define COMPANY_MODE 0
//#define SNF_ARRY_SIZE 500 
#define u_int32_t unsigned long
//#define JSON_FILE "/tmp/plugin/T1_V2.2.10/virtual_id.json"
#define JSON_FILE "/tmp/feature_lib/virtual_id.json"
u_int32_t mask_num;
u_int32_t loc_ip_num;
u_int32_t sep_ip_num;
u_int32_t net_num;
unsigned long br0IP;
int monitor_mode;
char check_mac[2];
//char certifi_ip[20];
//char certifi_port[8];
int ap_mode;
char ip_net[20];
char ap_mac[20];
char ap_mac_t[20];
char ap_ssid[40];
char ap_id[22];
char network_card[] = "br1:0";
char LOCATION_ID[16];
char LOCATION_TYPE[2];
char longitude[20];
char latitude[20];
char isp_id[4];
//char mac_list[300];
//char mac_login_list[1000];
struct server_ip_list *center_ip;
struct list_head  pc_hash_list;
//struct list_head  package_hash_list;
extern struct sniffer_data snf_data_arry[SNF_ARRY_SIZE];
extern unsigned int packet_need_to_deal;

void sniffer_data_deal(void * arg)
{
	int deal_index = 0;
	while(1)
	{
	//	pthread_mutex_lock(&snf_data_arry[deal_index].mutex);
		if (packet_need_to_deal == 0)
		{
	//		pthread_mutex_unlock(&snf_data_arry[deal_index].mutex);
			usleep(10);
			continue;
		}

		analysis_pack(snf_data_arry[deal_index].buffer, snf_data_arry[deal_index].data_size);
		packet_need_to_deal--;

	//	pthread_mutex_unlock(&snf_data_arry[deal_index].mutex);

		//printf("deal_index = %d \n",deal_index);
		deal_index++;

		if (deal_index >= SNF_ARRY_SIZE)
			deal_index = 0;
	}
}

void getmode()
{
}

void AEI_get_wan_ip()
{	
	int fd;	
	struct ifreq intf;	
	struct sockaddr* addr_tmp;		
	if((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)	
	{		
		printf("socket error!\n");		
		return;	
	}	
	addr_tmp = malloc(sizeof(struct sockaddr));
	if(addr_tmp == NULL)	
	{		
		close(fd);		
		return;
	}
	strcpy(intf.ifr_name, network_card);
	if(ioctl(fd, SIOCGIFADDR, &intf) != -1)	
	{		
		memcpy(addr_tmp,&(intf.ifr_addr),sizeof(struct sockaddr));
		strcpy(ip_net, inet_ntoa(((struct sockaddr_in *)addr_tmp)->sin_addr));	
	}	
	close(fd);
	free(addr_tmp);	
	return;
}

void get_ap_mac(void)
{
	char mac_buf[32] = "";
	char ap_mac_n[20] = "";
	executeCMD("lsap --mac", mac_buf);
	strncpy(ap_mac,mac_buf,strlen(mac_buf)-1);

//	char *mac = "00:01:7A:3A:B7:92";
//	strcpy(ap_mac,mac);
	
}
char loc_ip[16] = "";
void get_ip_mask(void)
{
	struct sockaddr_in *sin;
	struct ifreq ifr;
	int socket_fd;
	char mask[16] = "";
	char mac[20] = "";
	int i = 0;
	char dev_buf[16] = "";
	char net_card[16] = "";
	if((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		perror("socket");
		return;
	}
	executeCMD("lsap --devices", dev_buf);
	strncpy(net_card,dev_buf,strlen(dev_buf)-1);
	//if(!strlen(net_card))
	//	return;
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, net_card);
	memset(&sin, 0, sizeof(sin));
	if(ioctl(socket_fd, SIOCGIFADDR, &ifr) != -1)
	{
		sin = (struct sockaddr_in *)&ifr.ifr_addr;
		strcpy(loc_ip, inet_ntoa(sin->sin_addr));
		printf("IP address : %s------", loc_ip);
	}else{
		perror("ioctl");
		return;
	}
	if(ioctl(socket_fd, SIOCGIFNETMASK, &ifr) != -1)
	{
		sin = (struct sockaddr_in *)&ifr.ifr_broadaddr;
		strcpy(mask, inet_ntoa(sin->sin_addr));
		printf("IP mask : %s", mask);
	}
	if(ioctl(socket_fd, SIOCGIFHWADDR, &ifr) != -1)	
	{		
		sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",\
		(unsigned char)ifr.ifr_hwaddr.sa_data[0],\
		(unsigned char)ifr.ifr_hwaddr.sa_data[1],\
		(unsigned char)ifr.ifr_hwaddr.sa_data[2],\
		(unsigned char)ifr.ifr_hwaddr.sa_data[3],\
		(unsigned char)ifr.ifr_hwaddr.sa_data[4],\
		(unsigned char)ifr.ifr_hwaddr.sa_data[5]);	
	}
//	for(;i < strlen(mac);i++)
//		ap_mac_t[i] = toupper(mac[i]);
//	printf("ap mac == %s \n",ap_mac_t);
	for(;i < strlen(mac);i++)
		ap_mac_t[i] = mac[i];
	printf("ap mac lower== %s \n",ap_mac_t);
	mask_num = inet_addr(mask);
	//loc_ip_num = inet_addr(loc_ip);
	//sep_ip_num = inet_addr("219.238.235.46");
	
//	net_num = mask_num & loc_ip_num;
	return;
}

void get_netword_card(void)
{
	char card_buf[32] = "";
	//executeCMD("lsap --wan_dev", card_buf);
	executeCMD("lsap --devices", card_buf);
	strncpy(network_card,card_buf,strlen(card_buf)-1);
}

void init_sniffer_data_deal()
{
#if 0
	struct thread_manage *snf_data_arry;
	int i;
	for(i = 0;i < 5;i++)
	{
		snf_data_arry = (struct thread_manage *)malloc(sizeof(struct thread_manage));
		malloc_sniffer_buffer(snf_data_arry, SNF_ARRY_SIZE);
		pthread_create(&(snf_data_arry->pthread), NULL, sniffer_data_deal,(void *)snf_data_arry );
		list_add_head(&(snf_data_arry->head), &package_hash_list);
	//	printf("FILE---%s----__LINE__---%d\n",__FILE__,__LINE__);
	}
	return;
#endif
}
void start_deal_package_bak()
{
#if 0
	int sock_raw;
	struct sockaddr saddr;
	int saddr_size;
	sock_raw = create_socket(network_card);
	if (sock_raw < 0)
	{
		printf("create socket error\n");
		return 1;
	}
	init_sniffer_data_deal();	
	struct thread_manage *snf_data_arry ,*n;
	while(1)
	{
		list_for_each_entry_safe(snf_data_arry, n, &package_hash_list, head)
		{
			saddr_size = sizeof saddr;
			snf_data_arry->snf_data[snf_data_arry->packet_index].data_size = 
				recvfrom(sock_raw, snf_data_arry->snf_data[snf_data_arry->packet_index].buffer,SNF_BUF_SIZE - 1, 0, &saddr, (socklen_t*)&saddr_size);
			pthread_mutex_lock(&snf_data_arry->snf_data[snf_data_arry->packet_index].mutex);
			if (snf_data_arry->snf_data[snf_data_arry->packet_index].data_size <= 0)
			{
				pthread_mutex_unlock(&snf_data_arry->snf_data[snf_data_arry->packet_index].mutex);
				continue;
			}
			snf_data_arry->packet_need_to_deal++;
			pthread_mutex_unlock(&snf_data_arry->snf_data[snf_data_arry->packet_index].mutex);
			snf_data_arry->packet_index++;

			if (snf_data_arry->packet_index >= SNF_ARRY_SIZE)
				snf_data_arry->packet_index = 0;
		}
	}
	return;
#endif
}
#if 0
void  get_network_ip(char *cmd)
{	
	char buf[100] = "";   	
	FILE *ptr;   	
	if((ptr=popen(cmd, "r")) != NULL){   		
		fgets(buf, 99, ptr);   			
		pclose(ptr);   		
		ptr = NULL;   		
		char *p = buf;		
		p += 3;		
		strncpy(ip_net,p,sizeof(ip_net) - 1);	
	}else		
		printf("popen %s error\n", cmd);   	
	if(!strlen(ip_net))
		AEI_get_wan_ip();
	return;
}
#endif
void  get_network_ip()
{
    struct sockaddr_in servaddr;
    int sockfd;
	short port = 9090;
    bzero(&servaddr,sizeof(servaddr));
	
    servaddr.sin_family=AF_INET;
    servaddr.sin_port=htons(port);
    servaddr.sin_addr.s_addr=inet_addr("123.196.122.43");
    sockfd=socket(AF_INET,SOCK_STREAM,0);
	struct timeval timeout={3,0};
    socklen_t timeout_len = sizeof(timeout);
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, timeout_len);
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, timeout_len);
	if(connect(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr))<0)
	{
		printf("%d\n",errno);
        return NULL;
	}
		char send_buf[1000] = "";
	strcpy(send_buf, "POST /wifiCenter/getWanIpServlet HTTP/1.1\r\nUser-Agent: TeamSoft WinInet Component\r\nHost: 123.196.122.43:9090\r\nContent-Length: 0\r\nConnection: close\r\nCache-Control: no-cache\r\n\r\n");
	write(sockfd,send_buf,strlen(send_buf));
	char buffer[1000] = "";
	read(sockfd,buffer,sizeof(buffer));
	char *p = strstr(buffer,"ip=");
	if(p != NULL)
		strncpy(ip_net,p + 3,sizeof(ip_net) - 1);	
	else
		AEI_get_wan_ip();
	close(sockfd);
	return;
}
void make_mac_del_colon(char *mac)
{
	int i = 0,j = 0;
	for(;i<17;i++)
	{
		if(i != 2 && i != 5 && i != 8 && i != 11 && i != 14)
		{
			mac[j] = ap_mac[i];
			j++;
		}
	}
	return ;
}

void get_apid()
{
	char mac[20] = "";
	make_mac_del_colon(mac);
	strcpy(LOCATION_ID,mac);
	sprintf(ap_id,"051426941%s",mac);
	return;
}

int hostToIp(char *hostname,char *ip_config)
{
	char **pptr;
	struct hostent *hptr;
	char str[20] = {'\0'};

    if((hptr = gethostbyname(hostname)) == NULL)
    {
        printf("host to ip error!\n");
        return 1;
    }

    switch(hptr->h_addrtype)
    {
        case AF_INET:
            pptr = hptr->h_addr_list;
            for(; *pptr != NULL; pptr++){
                printf("\taddress: %s\n", inet_ntop(hptr->h_addrtype, *pptr, str, sizeof(str)));
                sprintf(ip_config,"%s",inet_ntop(hptr->h_addrtype, *pptr, str, sizeof(str)));
                return 0;
            }
            break;
        default:
            printf("unknown address type!\n");
            break;
    }
    return 1;
}

void get_server_ip(char *temp)
{
    char *pos=NULL;
    struct server_ip_list *buff=NULL;
    pos=strtok(temp,",");
	char hostname[50] = {'\0'};
	while(pos)
	{
		hostToIp(pos,hostname);
		buff = malloc(sizeof(struct server_ip_list));
		buff->ip = malloc(strlen(hostname)+1);
		memset(buff->ip,0,strlen(hostname)+1);
		strcpy(buff->ip,hostname);

		buff->next = center_ip;
		center_ip = buff;
		pos=strtok(NULL,",");
	}

}

unsigned long getbr0IP(void)
{
	//char br1_ip[20] = "";
	//struct in_addr br1_Ip;
	//executeCMD("lsap --wan_ip", br1_ip);
	//inet_aton(br1_ip, &srcIp);
	//printf("br1 ip = %d \n",br1_Ip);
	//return br1_Ip;    
}
virtual_url_id_list *virtual_get_list = NULL;
int virtual_get_num = 0;
virtual_url_id_list *virtual_post_list = NULL;
int virtual_post_num = 0;
virtual_url_list *IMEI_IMSI_post_list = NULL;
int IMEI_IMSI_post_num = 0;
virtual_url_list *IMEI_IMSI_get_list = NULL;
int IMEI_IMSI_get_num = 0;

int parse_json(char *info)
{
	cJSON *cJsonObject = NULL;
	cJSON *cJsonFence = NULL;
	cJSON *cJsonFence3 = NULL;
	cJSON *cJsonArrarItem = NULL;
	int array_size=0,iCnt=0;

	cJSON *cjsonprotocol_type = NULL;
	cJSON *cjsonurl_flag = NULL;
	cJSON *cjsonstart_flag = NULL;
	cJSON *cjsonend_flag = NULL;
	cJSON *cjsonmail_flag = NULL;
	cJSON *cjsonurldecode_flag = NULL;
	cJSON *cjsondata_flag = NULL;
	cJSON *cjsonid_type = NULL;
	cJSON *cjsononly_url = NULL;

	if(NULL == (cJsonObject = cJSON_Parse(info)))
		printf("Error before: [%s]\n",cJSON_GetErrorPtr());

	else{
		if(NULL == (cJsonFence = cJSON_GetObjectItem(cJsonObject,"virtual_id_fence")))
			printf("cJSON cJSON_GetObjectItem cJson virtual_id_fence failed !\n");
		else{

			array_size = cJSON_GetArraySize(cJsonFence);
			for(iCnt=0;iCnt<array_size;iCnt++)
			{
				if(NULL == (cJsonArrarItem = cJSON_GetArrayItem(cJsonFence,iCnt)))
				{
			
					return ;
				}
				cjsonprotocol_type = cJSON_GetObjectItem(cJsonArrarItem,"protocol_type");
				cjsonurl_flag = cJSON_GetObjectItem(cJsonArrarItem,"url_flag");
				cjsonstart_flag = cJSON_GetObjectItem(cJsonArrarItem,"start_flag");
				cjsonend_flag = cJSON_GetObjectItem(cJsonArrarItem,"end_flag");
				cjsonmail_flag = cJSON_GetObjectItem(cJsonArrarItem,"mail_flag");
				cjsonurldecode_flag = cJSON_GetObjectItem(cJsonArrarItem,"urldecode_flag");
				cjsondata_flag = cJSON_GetObjectItem(cJsonArrarItem,"data_flag");
				cjsonid_type = cJSON_GetObjectItem(cJsonArrarItem,"id_type");
				cjsononly_url = cJSON_GetObjectItem(cJsonArrarItem,"only_url");
				if (NULL==cjsonprotocol_type || NULL==cjsonurl_flag || NULL==cjsonstart_flag || NULL==cjsonend_flag  \					
					|| NULL==cjsondata_flag || NULL==cjsonid_type) 			
				{							
					printf("%s(%d), fail to get array item!\n", __func__, __LINE__);							
					continue ;					
				}
				if(strstr(cjsonprotocol_type->valuestring,"GET"))
				{
					virtual_get_list= (virtual_url_id_list *)realloc(virtual_get_list, (virtual_get_num + 1) * sizeof(virtual_url_id_list));
					virtual_get_list[virtual_get_num].protocol_type = strdup(cjsonprotocol_type->valuestring);
					virtual_get_list[virtual_get_num].url = strdup(cjsonurl_flag->valuestring);
					virtual_get_list[virtual_get_num].start_flag = strdup(cjsonstart_flag->valuestring);
					virtual_get_list[virtual_get_num].end_flag = strdup(cjsonend_flag->valuestring);
					virtual_get_list[virtual_get_num].mail_flag = strdup(cjsonmail_flag->valuestring);
					virtual_get_list[virtual_get_num].urldecode_flag = strdup(cjsonurldecode_flag->valuestring);
					virtual_get_list[virtual_get_num].data_flag = strdup(cjsondata_flag->valuestring);
					virtual_get_list[virtual_get_num].id_type = strdup(cjsonid_type->valuestring);
					virtual_get_list[virtual_get_num].only_url = strdup(cjsononly_url->valuestring);
					
					virtual_get_num ++;
				}
				else if(strstr(cjsonprotocol_type->valuestring,"POST"))
				{
					virtual_post_list= (virtual_url_id_list *)realloc(virtual_post_list, (virtual_post_num + 1) * sizeof(virtual_url_id_list));
					virtual_post_list[virtual_post_num].protocol_type = strdup(cjsonprotocol_type->valuestring);
					virtual_post_list[virtual_post_num].url = strdup(cjsonurl_flag->valuestring);
					virtual_post_list[virtual_post_num].start_flag = strdup(cjsonstart_flag->valuestring);
					virtual_post_list[virtual_post_num].end_flag = strdup(cjsonend_flag->valuestring);
					virtual_post_list[virtual_post_num].mail_flag = strdup(cjsonmail_flag->valuestring);
					virtual_post_list[virtual_post_num].urldecode_flag = strdup(cjsonurldecode_flag->valuestring);
					virtual_post_list[virtual_post_num].data_flag = strdup(cjsondata_flag->valuestring);
					virtual_post_list[virtual_post_num].id_type = strdup(cjsonid_type->valuestring);
					virtual_post_list[virtual_post_num].only_url = strdup(cjsononly_url->valuestring);
					virtual_post_num ++;
				}	
				
			}
		}
		if(NULL == (cJsonFence3 = cJSON_GetObjectItem(cJsonObject,"IMEI_IMSI_id_fence")))
			printf("cJSON cJSON_GetObjectItem cJson IMEI_IMSI_id_fence failed !\n");
		else
		{
			array_size = cJSON_GetArraySize(cJsonFence3);

			for(iCnt=0;iCnt<array_size;iCnt++)
			{
				if(NULL == (cJsonArrarItem = cJSON_GetArrayItem(cJsonFence3,iCnt)))
				{
					printf("%s(%d),fail to get array!",__func__,__LINE__);
					return ;
				}
				cjsonprotocol_type = cJSON_GetObjectItem(cJsonArrarItem,"protocol_type");
				cjsonurl_flag = cJSON_GetObjectItem(cJsonArrarItem,"url_flag");
				cjsonstart_flag = cJSON_GetObjectItem(cJsonArrarItem,"start_flag");
				cjsonend_flag = cJSON_GetObjectItem(cJsonArrarItem,"end_flag");
				cjsonurldecode_flag = cJSON_GetObjectItem(cJsonArrarItem,"urldecode_flag");
				cjsondata_flag = cJSON_GetObjectItem(cJsonArrarItem,"data_flag");
				cjsonid_type = cJSON_GetObjectItem(cJsonArrarItem,"id_type");
				cjsononly_url = cJSON_GetObjectItem(cJsonArrarItem,"only_url");
				if (NULL==cjsonprotocol_type || NULL==cjsonurl_flag || NULL==cjsonstart_flag || NULL==cjsonend_flag  \					
					|| NULL==cjsondata_flag || NULL==cjsonid_type) 			
				{							
					printf("%s(%d), fail to get array item!\n", __func__, __LINE__);							
					continue ;					
				}
				if(strstr(cjsonprotocol_type->valuestring,"GET"))
				{
					IMEI_IMSI_get_list= (virtual_url_list *)realloc(IMEI_IMSI_get_list, (IMEI_IMSI_get_num + 1) * sizeof(virtual_url_list));
					IMEI_IMSI_get_list[IMEI_IMSI_get_num].protocol_type = strdup(cjsonprotocol_type->valuestring);
					IMEI_IMSI_get_list[IMEI_IMSI_get_num].url = strdup(cjsonurl_flag->valuestring);
					IMEI_IMSI_get_list[IMEI_IMSI_get_num].start_flag = strdup(cjsonstart_flag->valuestring);
					IMEI_IMSI_get_list[IMEI_IMSI_get_num].end_flag = strdup(cjsonend_flag->valuestring);
					IMEI_IMSI_get_list[IMEI_IMSI_get_num].urldecode_flag = strdup(cjsonurldecode_flag->valuestring);
					IMEI_IMSI_get_list[IMEI_IMSI_get_num].data_flag = strdup(cjsondata_flag->valuestring);
					IMEI_IMSI_get_list[IMEI_IMSI_get_num].id_type = strdup(cjsonid_type->valuestring);
					IMEI_IMSI_get_list[IMEI_IMSI_get_num].only_url = strdup(cjsononly_url->valuestring);
					IMEI_IMSI_get_num ++;
				}
				else if(strstr(cjsonprotocol_type->valuestring,"POST"))
				{
					IMEI_IMSI_post_list= (virtual_url_list *)realloc(IMEI_IMSI_post_list, (IMEI_IMSI_post_num + 1) * sizeof(virtual_url_list));
					IMEI_IMSI_post_list[IMEI_IMSI_post_num].protocol_type = strdup(cjsonprotocol_type->valuestring);
					IMEI_IMSI_post_list[IMEI_IMSI_post_num].url = strdup(cjsonurl_flag->valuestring);
					IMEI_IMSI_post_list[IMEI_IMSI_post_num].start_flag = strdup(cjsonstart_flag->valuestring);
					IMEI_IMSI_post_list[IMEI_IMSI_post_num].end_flag = strdup(cjsonend_flag->valuestring);
					IMEI_IMSI_post_list[IMEI_IMSI_post_num].urldecode_flag = strdup(cjsonurldecode_flag->valuestring);
					IMEI_IMSI_post_list[IMEI_IMSI_post_num].data_flag = strdup(cjsondata_flag->valuestring);
					IMEI_IMSI_post_list[IMEI_IMSI_post_num].id_type = strdup(cjsonid_type->valuestring);
					IMEI_IMSI_post_list[IMEI_IMSI_post_num].only_url = strdup(cjsononly_url->valuestring);
					IMEI_IMSI_post_num ++;
				}	
				
			}
		}
		cJSON_Delete(cJsonObject);
	}
}

void wget_json()
{
	//char mk[32] = "mkdir /tmp/feature_lib";
	//system(mk);
	if(!access("/tmp/feature_lib/virtual_id.json", F_OK))
	{
		printf("remove old json\n");
		char rm[64] = "rm /tmp/feature_lib/virtual_id.json";
		system(rm);
		printf("\n");
	}
	if(access("/tmp/feature_lib/virtual_id.json", F_OK))
	{
		printf("begin download json\n");
		printf("\n");
		char wget[128] = "wget -P /tmp/feature_lib/ http://kk.bjbywx.com:8076/version/virtual_id.json";
		system(wget);
		printf("\n");
	}
	char ulimit[64] = "ulimit -s unlimited";//防止过滤规则挂
	system(ulimit);
}
int get_json_info()
{

	FILE *fd;
	//char pwd[16] = "";
	//char path[32] = "";
	//executeCMD("pwd", pwd);
	//sprintf(path,"%s/%s",pwd,"virtual_id.json");
	//printf("path  %s \n",path);
	//if((fd = fopen(path,"rb")) == NULL){
	while((fd = fopen(JSON_FILE,"rb")) == NULL){
		printf("%s isn't existence\n",JSON_FILE);
		sleep(30);
		wget_json();
	//	printf("%s isn't existence\n",path);
		//exit(-1);
	}
	fseek(fd,0,SEEK_END);
	long len=ftell(fd);
	fseek(fd,0,SEEK_SET);
	char *data=(char *)malloc(len+1);
	fread(data,1,len,fd);
	fclose(fd);
	int res = parse_json(data);
	if(res)
		printf("check the file :%s\n",JSON_FILE);
	free(data);
}



int get_ap_info()
{
	char ip_config[100] = "";
	get_ssid();
//	get_network_ip("curl -s --connect-timeout 1 -m 2 123.196.122.43:9090/wifiCenter/getWanIpServlet");
	get_network_ip();
	get_ip_mask();
	get_ap_mac();
	get_apid();
	//br0IP = getbr0IP();
//	getmode();
//	getnvram("l7mon_ground_id",LOCATION_ID);
//	if(!strlen(LOCATION_ID))
//		return 0;
//	getnvram("Site_location_longitude",longitude);
	if(!strlen(longitude))
		strcpy(longitude,"111.222111");
//	getnvram("Site_location_latitude",latitude);
	if(!strlen(latitude))
		strcpy(latitude,"11.222111");
//	getnvram("isp_id", isp_id);
	if(!strlen(isp_id))
		strcpy(isp_id,"99");
//	getnvram("Online_site_type",LOCATION_TYPE);
	if(!strlen(LOCATION_TYPE))
		strcpy(LOCATION_TYPE,"0");
//	getnvram("l7mon_serverip0",ip_config);
//	if(!strlen(ip_config))
//		strcpy(ip_config,"61.161.255.123");
	hostToIp("update.souwifi.cn",ip_config);
	//printf("get server ip == %s \n",ip_config);
	while(strlen(ip_config) == 0)
	{
		hostToIp("update.souwifi.cn",ip_config);
		//printf("get server ip == %s \n",ip_config);
		sleep(10);
	}
	//hostToIp("www.baidu.com",ip_config);
	get_server_ip(ip_config);
	//printf("net ip : %s -- ap mac : %s --- ssid %s : \n",ip_net,ap_mac,ap_ssid);
	return 1;

}

int init_session_list()
{
	INIT_LIST_HEAD(&pc_hash_list);
	//if(!monitor_mode)
	//	INIT_LIST_HEAD(&package_hash_list);
	init_session_filter_list();
}


int main(int argc, char **argv)
{
#if 0
	get_netword_card();
	if(!strlen(network_card))
	{
		printf("Please input interface name in network_card file\n");
		return 0;
	}
	char path[32] = "";
	executeCMD("pwd", path);
	strcat(path,"/virtual_id");
	printf("path  %s \n",path);
#endif
	//printf("time %s date %s \n",__TIME__,__DATE__);
	char ver[20];
	sprintf(ver,"%s,%s",__DATE__,__TIME__);
	write_to_file_t("/tmp/plugin/version","w+",ver);
	if(!get_ap_info())
		return 0;
	wget_json();
	get_json_info();
	init_session_list();
	//start_online_recv();
//	start_online_check();
//	start_fifo_info();
//	if(monitor_mode == 0)
//		start_arp_info();
    start_heartbeat();
	start_file_info_deal();
	start_deal_package();
	return 0;
}
