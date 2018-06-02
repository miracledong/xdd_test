#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <syslog.h>
#include <stdio.h>
#include <stdio.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <sys/types.h>
#include <dirent.h>
#include <stddef.h>
#include <time.h>
#include <errno.h>
//#include "recv_msg.h"
#include "list.h"
#include "send_util.h"
#include "passenger_info.h"
#include "sniffer_def.h"
//#include "decrypt.h"
#include "des.h"
#include "base64.h"
#include "encrypt.h"
#define EVENT_SIZE  (sizeof(struct inotify_event))
#define BUF_LEN     (1024 * (EVENT_SIZE + 16))
#define PAIBO4_3_1 1
int SERVER_TCP_PORT = 18190;
int SERVER_UDP_PORT = 18198;
extern char ip_net[20];
extern char ap_mac[20];
extern char ap_ssid[40];
extern char ap_id[22];
extern char network_card[20];
extern char LOCATION_ID[16];
extern char LOCATION_TYPE[2];
extern char longitude[20];
extern char latitude[20];
extern char isp_id[4];
extern char mac_list[300];
extern struct server_ip_list *center_ip;
extern struct list_head pc_hash_list;
//extern struct list_head package_hash_list;
#define SEND_BUFF_SIZE 8192
#define USR_OFFLINE_PORT 50010
#define USR_ONLINE_PORT 50001
#define RECV_LENGTH 16
extern int monitor_mode;
extern char check_mac[2];
//extern char certifi_ip[20];
//extern char certifi_port[8];

int send_login(struct login_s *login_data,int IsFree);

int do_des_crypt(char *inbuf, int inlen, char *outbuf, int *outlen)
{

	int i = 0;int tmplen=0;
	unsigned char key[] = "by$@hdtv";
	unsigned char iv[] = "salt#&@!";
	int size=inlen;
	des_setparity(key);
	pad(inbuf,&size);
	s_des_encrypt(key,iv,inbuf,&size);
	memcpy(outbuf,inbuf,size);
	*outlen=size;
	return 0;
}
void sendUDPmsg(char *ip_str, int port, char *msg)
{

	struct sockaddr_in  server_address;

	char buffer[SEND_BUFF_SIZE]="\0", msg1[SEND_BUFF_SIZE]="";
	int sockc = socket(AF_INET,SOCK_DGRAM,0);

	int len = sizeof(server_address);

	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = inet_addr(ip_str);
	server_address.sin_port = htons(port);

	int ret=0;int outlen=0;
	//printf("port = %d\n",port);
	printf("\nsend udp  msg:%s\n", msg);
	do_des_crypt(msg,  strlen(msg), msg1,&outlen);

	Base64Encode(buffer,msg1, outlen);
	errno=0;
	do{
		sendto(sockc,buffer,strlen(buffer),0,(struct sockaddr*)&server_address,len);
//		printf("\nsend udp  buffer:%s\n", buffer);

	}while(0);

	close(sockc);

}

int sendTCPmsg(char *ip_str, int port, char *msg)
{
//	printf("TCP -----IP:%s------port:%d\n",ip_str,port);
	struct sockaddr_in  server_address;
	char buffer[SEND_BUFF_SIZE]="", msg1[SEND_BUFF_SIZE]="";
	char msg2[SEND_BUFF_SIZE] = "";
	int sockc = socket(AF_INET,SOCK_STREAM,0);
	int ret = 0, outlen = 0;
	int len = sizeof(server_address);
	int flags = fcntl(sockc, F_GETFL, 0);
	char *send_flage;
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = inet_addr(ip_str);
	server_address.sin_port = htons(port);
	memcpy(msg2,msg,strlen(msg));
	printf("\nsend tcp msg:%s \n", msg);
	do_des_crypt(msg,  strlen(msg), msg1,&outlen);
	Base64Encode(buffer,msg1, outlen);
	struct timeval timeout={3,0};
	socklen_t timeout_len = sizeof(timeout);
	setsockopt(sockc, SOL_SOCKET, SO_SNDTIMEO, &timeout, timeout_len);
	fcntl(sockc, F_SETFL, flags | O_NONBLOCK);
	if (connect(sockc, (struct sockaddr*)&server_address, sizeof(server_address)) < 0)
	{
		if(errno != EINPROGRESS && errno != EWOULDBLOCK) 
			return; 
		struct timeval tm;
		tm.tv_sec = 5;
		tm.tv_usec = 0;
		fd_set wset;
		FD_ZERO(&wset); 
		FD_SET(sockc, &wset); 
		int n = select(sockc+1, NULL, &wset, NULL, &tm);
		if(n < 0) 
		{ 
			perror("select()"); 
			close(sockc); 
			return; 
		} 
		else if (0 == n) 
		{
			printf("sendTCPmsg connect timeout!\n");
			close(sockc); 
			return; 
		} 
		//else 
			//printf("sendTCPmsg connect success!\n");
	}
	errno=0;
	do
	{
		ret = send(sockc,buffer,strlen(buffer),0);
		send_flage = strerror(errno);
	}while(0);
	memset(buffer, 0, SEND_BUFF_SIZE);
	close(sockc);
	return;
}

char * my_strdup(char *str)
{
	char *p = NULL;
	if(str)
	{
		p = malloc(strlen(str)+1);
		memcpy(p, str, strlen(str)+1);
	}
	return p;
}



void make_virtual_info(struct virtual_info *login_data,char *username,char *id_type,char *login_time)
{
	login_data->id = my_strdup(username);
	login_data->id_type = my_strdup(id_type);
	login_data->time = my_strdup(login_time);
	login_data->name = my_strdup(username);
	return;
}

int send_virtual_login_data(char *username, char *id_type, struct panssenger_info *passenger_tmp)
{
	printf("virtual info :%s id_type :%s \n",username,id_type);
	struct login_data_list_s *login_data_list = NULL;
	struct login_s *login_data = (struct login_s *)malloc(sizeof(struct login_s));
	memset(login_data,0,sizeof(struct login_s));
	if(NULL == find_login_data_by_id_type(username, id_type, passenger_tmp))
	{
		login_data_list = malloc(sizeof(*login_data_list));
		login_data_list->login_data= malloc(sizeof(struct virtual_info));
		memset(login_data_list->login_data, 0, sizeof(struct virtual_info));
		make_login_data(login_data,passenger_tmp);
		if(login_data->id)
		{
			free(login_data->id);
			login_data->id = my_strdup(username);
		}
		if(login_data->id_type)
		{
			free(login_data->id_type);
			login_data->id_type = my_strdup(id_type);
		}    
		if(login_data->login_time)
		{
			memset(login_data->login_time,0,strlen(login_data->login_time));
			make_time_str(login_data->login_time);
		}
		make_virtual_info((struct virtual_info *)login_data_list->login_data,username,id_type,login_data->login_time);
		add_login_data_to_passenger(login_data_list, passenger_tmp);
		send_login(login_data,0);
		//	printf("Add:%s %s\n",((struct login_s*)(passenger_tmp->login_list->login_data))->id,((struct login_s*)(passenger_tmp->login_list->login_data))->id_type);
	}
	return 1;
}




void make_logout_data(struct logout_s *data, struct panssenger_info *info, char *logout_time)
{
	data->version = my_strdup(info->version);
	data->event_type = my_strdup("41");
	data->doc_version = my_strdup(info->doc_version);
	data->auth_type = my_strdup(info->auth_type);
	data->auth_account = my_strdup(info->auth_account);
	data->id_type = my_strdup(info->ID_type);
	data->id = my_strdup(info->ID);
	data->id_name = my_strdup(info->id_name);
	data->app_company = my_strdup(info->app_company);
	data->app_name = my_strdup(info->app_name);
	data->app_version = my_strdup(info->app_version);
	data->app_authcode = my_strdup(info->app_authcode);
	data->location_code = my_strdup(info->location_code);
	data->location_type = my_strdup(info->location_type);
	data->login_time = my_strdup(info->login_time);
#if 0
	char time_str[40] = "";
	struct tm tm;
	time_t time_now = time(0);
	localtime_r(&time_now, &tm);
	sprintf(time_str,"%d-%02d-%02d %02d:%02d:%02d", 1900+tm.tm_year, tm.tm_mon+1, tm.tm_mday,tm.tm_hour,tm.tm_min, tm.tm_sec);
#endif
	data->logout_time = my_strdup(logout_time);
	//	data->logout_time = my_strdup(info->logout_time);
	data->mac = my_strdup(info->mac);
	data->lan_ip = my_strdup(info->lan_ip);
	data->source_ip4 = my_strdup(info->source_ip4);
	data->source_ip6 = my_strdup(info->source_ip6);
	data->source_startport4 = my_strdup(info->source_startport4);
	data->source_endport4 = my_strdup(info->source_endport4);
	data->source_startport6 = my_strdup(info->source_startport6);
	data->source_endport6 = my_strdup(info->source_endport6);
	data->apid = my_strdup(info->apid);
	data->apmac = my_strdup(info->apmac);
	data->longitude = my_strdup(info->longitude);
	data->latitude = my_strdup(info->latitude);
	data->rssi = my_strdup(info->rssi);
	data->session_id = my_strdup(info->session_id);
	data->x = my_strdup(info->x);
	data->y = my_strdup(info->y);
	data->imsi = my_strdup(info->imsi);
	data->device_id = my_strdup(info->device_id);
	data->terminal_system = my_strdup(info->terminal_system);
	data->terminal_brand = my_strdup(info->terminal_brand);
	data->terminal_brandtype = my_strdup(info->terminal_brandtype);
	data->source = my_strdup(info->source);
	data->isp_id = my_strdup(info->isp_id);
	data->wan_ip = my_strdup(info->wan_ip);
	data->source_port = my_strdup(info->source_port);
	data->ssid = my_strdup(info->ssid);
	data->associated = my_strdup(info->associated);
	data->floor = my_strdup(info->floor);
	data->login_type = my_strdup(info->login_type);
	data->plastersign = my_strdup(info->plastersign);
	//	data->binding_id_group = my_strdup(info->binding_id_group);
	//	data-> = my_strdup(info->);
	return;
}


void make_binding_group_id(char *data,struct panssenger_info *info)
{
	struct login_data_list_s *login_data_list_tmp = NULL;
	struct login_data_list_s *p=NULL;
	struct virtual_info *login_data_tmp = NULL;
	if(info)
		login_data_list_tmp = info->login_list;
	if(login_data_list_tmp && login_data_list_tmp->login_data)
		login_data_tmp = (struct virtual_info *)login_data_list_tmp->login_data;
	while(login_data_tmp)
	{
		if(strlen(data)<2000)
		{
			sprintf(data + strlen(data),"%s\03%s\03%s\03%s\03\02",login_data_tmp->id,login_data_tmp->id_type,login_data_tmp->time,login_data_tmp->name);
		}
		free_sent_data((char **)login_data_tmp, sizeof(*login_data_tmp)/(sizeof(char *)));
		p = login_data_list_tmp;
		login_data_tmp = NULL;	
		login_data_list_tmp = (struct login_data_list_s*)login_data_list_tmp->next;
		if(login_data_list_tmp && login_data_list_tmp->login_data)
			login_data_tmp = (struct virtual_info *)login_data_list_tmp->login_data;
		free(p);
	}
	//printf("binding info == %s\n",data);
	info->login_list = NULL;
	return;
}

void make_logout_time(char *logout_time)
{
	char time_str[40] = "";
	struct tm tm;
	time_t time_now = time(0);
	localtime_r(&time_now, &tm);
	sprintf(time_str,"%d-%02d-%02d %02d:%02d:%02d", 1900+tm.tm_year, tm.tm_mon+1, tm.tm_mday,tm.tm_hour,tm.tm_min, tm.tm_sec);
	logout_time = my_strdup(time_str);
	return;
}

int send_logout(struct panssenger_info *info, char *logout_time)
{
	char msg[SEND_BUFF_SIZE]="";
	struct logout_s logout_data;
	struct logout_s *data = &logout_data;
	struct server_ip_list *temp = center_ip;	
	make_logout_data(data, info, logout_time);
	//	make_logout_time(data->logout_time);
	data->binding_id_group = (char *)malloc(2048);
	memset(data->binding_id_group,0,2048);
	make_binding_group_id(data->binding_id_group,info);
	while(temp)
	{
		memset(msg,0,sizeof(msg));
		build_send_msg(msg, (char **)data, sizeof(*data)/(sizeof(char *)));
		//printf("\nsend_logout msg:%s\n",msg);
		sendTCPmsg(temp->ip, SERVER_TCP_PORT, msg);
		temp = temp->next;
	}
	free_sent_data((char **)data, sizeof(*data)/(sizeof(char *)));
	return 0;
}

int remove_pc_from_allow_list(struct pc_t *pc_tmp, char *logout_time)
{
	if(!(list_empty(&pc_tmp->head)))
		list_del(&pc_tmp->head);
	send_logout(&(pc_tmp->passenger_info),logout_time);
	//	free_passenger_data(&(pc_tmp->passenger_info));
	free(pc_tmp);
	pc_tmp = NULL;
	return 1;
}
#if 0
void user_offline_recv()
{
	struct pc_t *pc_tmp, *n;
	int sock;
	struct sockaddr_in add;
	char message[RECV_LENGTH] = {'\0'};
	int sin_len = sizeof(add);
	char write_msg[50] = {'\0'};
	char time_str[30] = {'\0'};
	char cmd[40] = {'\0'};
	bzero(&add,sizeof(struct sockaddr_in));
	add.sin_family = AF_INET;
	add.sin_port = htons(USR_OFFLINE_PORT); 
	add.sin_addr.s_addr = htonl(INADDR_ANY);
	sock = socket(AF_INET,SOCK_DGRAM,0);
	bind(sock, (struct sockaddr *)&add, sizeof(add));
	while(1)
	{
		memset(message,0,sizeof(message));
		recvfrom(sock,message,sizeof(message),0,(struct sockaddr *)&add, &sin_len);

		list_for_each_entry_safe(pc_tmp, n, &pc_hash_list, head)
		{
			if(strcmp(inet_ntoa(*(struct in_addr *)&pc_tmp->src_ip),message) == 0)
			{
				remove_pc_from_allow_list(pc_tmp->src_ip);
#ifdef IPTABLES
				sprintf(cmd,"sh ./refuse_ip.sh %s",message);
				system(cmd);
#endif
				printf("remove ip --- %s\n",message);
			}
		}
	}
	return;
}

#define USR_OFFLINE_PORT 50010
void user_offline_send(char *buf)
{
	int sock;
	struct sockaddr_in address;
	bzero(&address, sizeof(address)); /*  empty data structure */
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = inet_addr("127.0.0.1");
	address.sin_port = htons(USR_OFFLINE_PORT);
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	sendto(sock, buf, strlen(buf), 0, (struct sockaddr *)&address, sizeof(address)); /* address is the target of the message send */
	close (sock);
	return;
}

void user_online_check(void)
{
	time_t time_now = 0;
	struct pc_t *pc_tmp, *n;
	int ret;
	char message[20] = "";
	char time_str[30] = {'\0'}; 
	while(1)
	{
		time_now = time(0);
		list_for_each_entry_safe(pc_tmp, n, &pc_hash_list, head)
		{
			printf("user last vist time =%ld current time=%ld srcip:%s\n"\
					,pc_tmp->passenger_info.last_visit_time,time_now,inet_ntoa(*(struct in_addr *)&pc_tmp->src_ip));
			if(pc_tmp->passenger_info.last_visit_time + 300 < time_now)
			{
				memset(message,0,sizeof(message));
				strcpy(message,inet_ntoa(*(struct in_addr *)&pc_tmp->src_ip));
				user_offline_send(message);
				remove_pc_from_allow_list(pc_tmp);
				printf("remove pc list on checked!\n");
			}
		}
		sleep(60);
	}
	pthread_t online_thread;
	if(ret != 0)
	{
		printf("create online_checked_thread failed!\n");
		return ;
	}
	return;
}

void start_online_check(void)
{
	int ret;
	pthread_t online_check;
	ret = pthread_create(&online_check,NULL,(void *)user_online_check,NULL);
	if(ret != 0)
	{
		printf("create online_checked_thread failed!\n");
		return ;
	}
	return;
}
#endif
#if 0
void readfile_get_mac(char *srcip,char *mac)
{
	char buffer[1024];
	FILE *fp;
	fp=fopen("/proc/net/arp","r");
	if(fp==NULL)
	{
		perror("file not exists\n");
		exit(1);
	}
	char *pos=NULL;
	char ip[20]="";
	int ret = 0;
	while(fgets(buffer,sizeof(buffer),fp)!=NULL)
	{
		pos = strstr(buffer," ");
		memset(ip,0,sizeof(ip));
		strncpy(ip,buffer,pos-buffer);
		ret = strcmp(ip,srcip);
		if(ret==0)
		{
			pos = strstr(buffer,":");
			if(pos)
				strncpy(mac,pos-2,17);
			fclose(fp);
			return;
		}
	}
	fclose(fp);
	return;
}
#endif
void executeCMD(const char *cmd, char *result)
{
	char buf_ps[1024];
	char ps[1024] = {0};
	FILE *ptr;
	strcpy(ps, cmd);
	if((ptr=popen(ps, "r"))!=NULL)
	{
		while(fgets(buf_ps, 1024, ptr)!=NULL)
		{
			strcat(result, buf_ps);
			if(strlen(result)>1024)
				break;
		}
		pclose(ptr);
		ptr = NULL;
	}
	else
	{
		printf("popen %s error\n", ps);
	}
}

void get_ssid()
{
#if 0
	char buf[100] = "";
	FILE *ptr;
	int i = 0;
	if((ptr = popen("iwconfig ra0","r")) != NULL)
	{
		fgets(buf,99,ptr);
		pclose(ptr);
		char *p = strstr(buf,"ESSID:\"");
		if(p)
		{
			p += 7;
			for(;*p != '\"';i++)
				ap_ssid[i] = *(p++);
		}
	}
#endif
	char ssid_buf[32] = "";
	//char ssid[32] = "";
	//char *p = NULL;
	executeCMD("lsap --ssid", ssid_buf);
	//if(strstr(p,"ssid="))
	//{
	//	p += 5;
	//	strcpy(ssid,p);
	//	if(!strlen(ssid))
	//		return 1;
	//	printf("apssid : %s",ssid);
	//}
		strncpy(ap_ssid,ssid_buf,strlen(ssid_buf)-1);

	if(!strlen(ap_ssid))
		strcpy(ap_ssid,"BOYI_SOFT");
	return ;
}

void make_mac_add_colon(char *mac,char *sta_mac)
{
	char mac_tmp[20] = {'\0'};
	unsigned long i = 0,j = 0;
	mac_tmp[2] = mac_tmp[5] = mac_tmp[8] = mac_tmp[11] = mac_tmp[14] = '-';
	if(strlen(mac) == 0)
	{
		return ;
	}
	else if(strlen(mac) > 13)
	{
		//	for(;i < strlen(mac);i++)
		for(;i < 17;i++)
			sta_mac[i] = toupper(mac[i]);
		sta_mac[2] = sta_mac[5] = sta_mac[8] = sta_mac[11] = sta_mac[14] = '-';
	}
	else
	{
		for(; i < sizeof(mac_tmp); i++)
		{
			if(mac_tmp[i] != '-')
			{
				mac_tmp[i] = mac[j];
				j++;
				if(j == strlen(mac))
					break;
			}
		}
		for(i = 0;i < strlen(mac_tmp);i++)
			sta_mac[i] = toupper(mac_tmp[i]);
	}
	return;
}

void make_ip4_port(int *ip4_port_start,int *ip4_port_end,char *src_ip_str)
{
	char *p = NULL;
	char ip[20] = "";
	int i = 0;
	strcpy(ip,src_ip_str);
	p = strtok(ip,".");
	if(p != NULL)
	{
		for(;i < 3;i++)
		{
			p = strtok(NULL,".");
		}
	}
	if(p)
	{
		*ip4_port_end = atoi(p) * 200;
		*ip4_port_start = *ip4_port_end - 199;
	}
	else
	{
		*ip4_port_end = 1000;
		*ip4_port_start = 800;
	}
	return;
}
void make_rssi(char *rssi)
{
	int i = 0;
	srand((unsigned int) time(NULL));
	i = rand() % 80;
	sprintf(rssi,"-%d",i);
	return;
}
void make_session_id(char *session_id,char *mac)
{
	int i = 0;
	char sta_mac[20] = "";
	if(strlen(mac) == 17)
	{
		int j = 0;
		for(;i<17;i++)
		{
			if(i != 2 && i != 5 && i != 8 && i != 11 && i != 14)
			{
				sta_mac[j] = toupper(mac[i]);
				j++;
			}
		}
	}
	else
	{
		for(;i < strlen(mac);i++)
			sta_mac[i] = toupper(mac[i]);
	}
	sprintf(session_id,"%s%s%d",LOCATION_ID,sta_mac,time(0));
	return;
}

void make_x_y(int *x,int *y)
{
	srand((unsigned int) time(NULL));
	*x = rand() % 10;
	*y = rand() % 10;
	return;
}

#define BOYI_VERSION "WY-V"
#define PAIBO_4_3_1
int fill_passenger_info(struct passenger_info  * passenger_info, char *src_ip_str, char *mac,char *id_type,char *id,char *auth_type,char *login_time)
{
	int ip4_port_start = 0,ip4_port_end = 0,x = 0,y = 0;
	char sta_mac[20] = "",rssi[4] = "",session_id[64] = "";
	//time_t time_now = time(0);
	//struct tm *t = localtime(&time_now);
	struct panssenger_info * info = passenger_info;
	char wan_ip_buf[32] = "";
	char wan_ip[32] = "";
	executeCMD("lsap --wan_ip", wan_ip_buf);
	strncpy(wan_ip,wan_ip_buf,strlen(wan_ip_buf)-1);
	
	make_rssi(rssi);
	make_x_y(&x,&y);
	make_mac_add_colon(mac,sta_mac);
	make_ip4_port(&ip4_port_start,&ip4_port_end,src_ip_str);
	//	make_session_id(session_id,mac);
	make_session_id(session_id,sta_mac);
	strcpy(info->version,BOYI_VERSION);
	strcpy(info->event_type,"40");
#ifdef PAIBO_4_3
	strcpy(info->doc_version,"4.3");
#elif defined PAIBO_4_3_1
	strcpy(info->doc_version,"4.3.1");
#endif
	strcpy(info->auth_type,auth_type);
	strcpy(info->auth_account,id);
	strcpy(info->ID_type,id_type);
	strcpy(info->ID,id);
	/*
	   姓名/昵称	ID_NAME
	   APP厂商名称	APP_COMPANY
	   APP应用名称	APP_NAME
	   APP版本号	APP_VERSION
	   APP终端认证码	APP_AUTHCODE

*/
	strcpy(info->location_code,LOCATION_ID);
	//printf("loca id =%s \n",info->location_code);
	strcpy(info->location_type,LOCATION_TYPE);
	//sprintf(info->login_time,"%04d-%02d-%02d %02d:%02d:%02d", t->tm_year+1900, t->tm_mon+1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
	strcpy(info->login_time,login_time);
	strcpy(info->mac,sta_mac);
	strcpy(info->lan_ip,src_ip_str);
	strcpy(info->source_ip4,ip_net);
	/*
	   源外网IPv6地址	SOURCE_IP6
	   */
	sprintf(info->source_startport4,"%d",ip4_port_start);
	sprintf(info->source_endport4,"%d",ip4_port_end);
	/*
	   源外网IPv6起始端口号	SOURCE_STARTPORT6
	   源外网IPv6结束端口号	SOURCE_ENDPORT6
	   */
	strcpy(info->source_startport6,"0");
	strcpy(info->source_endport6,"0");
	strcpy(info->apid,ap_id);
	strcpy(info->apmac,ap_mac);
	strcpy(info->longitude,longitude);
	strcpy(info->latitude,latitude);
	strcpy(info->rssi,rssi);
	strcpy(info->session_id,session_id);
	//	strcpy(info->x,x);
	sprintf(info->x,"%d",x);
	//	strcpy(info->y,y);
	sprintf(info->y,"%d",y);
	/*
	   国际移动用户标识号IMSI	IMSI
	   终端操作系统	TERMINAL_SYSTEM
	   终端设备品牌	TERMINAL_BRAND
	   终端设备型号	TERMINAL_BRANDTYPE
	   */
	strcpy(info->source,"29");
	strcpy(info->isp_id,isp_id);
	strcpy(info->wan_ip,wan_ip);
	strcpy(info->source_port,"80");
	strcpy(info->ssid,ap_ssid);
	strcpy(info->associated,ap_ssid);
	/*
	   楼层	FLOOR
	   */
	strcpy(info->login_type,"30");
	strcpy(info->plastersign,"0");
	info->login_list = NULL;

	info->last_visit_time = time(0);
	return 0;
}



int make_login_data(struct login_s *data, struct panssenger_info *info)
{
	data->version = my_strdup(info->version);
	data->event_type = my_strdup(info->event_type);
	data->doc_version = my_strdup(info->doc_version);
	data->auth_type = my_strdup(info->auth_type);
	data->auth_account = my_strdup(info->auth_account);
	data->id_type = my_strdup(info->ID_type);
	data->id = my_strdup(info->ID);
	data->id_name = my_strdup(info->id_name);
	data->app_company = my_strdup(info->app_company);
	data->app_name = my_strdup(info->app_name);
	data->app_version = my_strdup(info->app_version);
	data->app_authcode = my_strdup(info->app_authcode);
	data->location_code = my_strdup(info->location_code);
	data->location_type = my_strdup(info->location_type);
	data->login_time = my_strdup(info->login_time);
	data->mac = my_strdup(info->mac);
	data->lan_ip = my_strdup(info->lan_ip);
	data->source_ip4 = my_strdup(info->source_ip4);
	data->source_ip6 = my_strdup(info->source_ip6);
	data->source_startport4 = my_strdup(info->source_startport4);
	data->source_endport4 = my_strdup(info->source_endport4);
	data->source_startport6 = my_strdup(info->source_startport6);
	data->source_endport6 = my_strdup(info->source_endport6);
	data->apid = my_strdup(info->apid);
	data->apmac = my_strdup(info->apmac);
	data->longitude = my_strdup(info->longitude);
	data->latitude = my_strdup(info->latitude);
	data->rssi = my_strdup(info->rssi);
	data->session_id= my_strdup(info->session_id);
	data->x = my_strdup(info->x);
	data->y = my_strdup(info->y);
	data->imsi = my_strdup(info->imsi);
	data->device_id = my_strdup(info->device_id);
	data->terminal_system = my_strdup(info->terminal_system);
	data->terminal_brand = my_strdup(info->terminal_brand);
	data->terminal_brandtype = my_strdup(info->terminal_brandtype);
	data->source = my_strdup(info->source);
	data->isp_id = my_strdup(info->isp_id);
	data->wan_ip = my_strdup(info->wan_ip);
	data->source_port = my_strdup(info->source_port);
	data->ssid = my_strdup(info->ssid);
	data->associated = my_strdup(info->associated);
	data->floor = my_strdup(info->floor);
	data->login_type = my_strdup(info->login_type);
	data->plastersign = my_strdup(info->plastersign);
	//data-> = my_strdup(info->);
	return 0;
}

int build_send_msg(char *msg, char *data[], int n)
{
	int i=0;
	char buf[2048]="";
	if(n>0){
		strcat(msg,data[0]);
		strcat(buf,data[0]);
	}
	for(i=1; i<n; i++)
	{
		if(data[i]){
			sprintf(msg+strlen(msg),"\01%s", data[i]);
			sprintf(buf+strlen(buf),"\01%s", data[i]);
		}
		else{
			sprintf(msg+strlen(msg),"\01");
			sprintf(buf+strlen(buf),"\01");
		}
	}
}


int free_sent_data(char *data[], int n)
{
	int i=0;
	for(i=0; i<n; i++)
	{
		if(data[i])
			free(data[i]);
		data[i]=NULL;
	}
}

int send_login(struct login_s *login_data,int IsFree)
{
	char msg[SEND_BUFF_SIZE]="";
	struct server_ip_list *temp = center_ip;
	struct login_s *data  = login_data;
	while(temp)
	{
		//  make_login_data((struct login_s*)&data, info);
		//printf("\n\n\n\n\n\n\nSendLoginIP:%s|\n",temp->ip);
		build_send_msg(msg, (char **)data, sizeof(*data)/(sizeof(char *)));		
		sendTCPmsg(temp->ip, SERVER_TCP_PORT, msg);

		memset(msg,0,SEND_BUFF_SIZE);
		temp=temp->next;
	}
	if(IsFree == 0)
	{
		free_sent_data((char **)data, sizeof(*data)/(sizeof(char *)));
		//	printf("FILE : %s LINE : %d\n",__FILE__,__LINE__);
	}
	return 0;
}

void Send_True_Info(void *args)
{
#if 0
	pthread_detach(pthread_self());
	struct pc_t *pc_info = (struct pc_t*)args;
	struct login_data_list_s *login_data_list = (struct login_data_list_s *)malloc(sizeof(*login_data_list));
	struct login_s *login_data = NULL;
	login_data_list->login_data = (char *)malloc(sizeof(struct login_s));
	memset(login_data_list->login_data, 0, sizeof(*(login_data_list->login_data)));
	make_login_data((struct login_s *)(login_data_list->login_data),&(pc_info->passenger_info));
	login_data = (struct login_s*)login_data_list->login_data;
	send_login(login_data,0);  
	free(login_data_list->login_data);
	free(login_data_list);
#endif
	pthread_detach(pthread_self());
	struct pc_t info; 
	struct pc_t *pc_info = &info;
	info = *(struct pc_t *)args;
	//	struct login_data_list_s *login_data_list = (struct login_data_list_s *)malloc(sizeof(*login_data_list));
	struct login_s *login_data = (struct login_s *)malloc(sizeof(struct login_s));
	//	login_data_list->login_data = (char *)malloc(sizeof(struct login_s));
	memset(login_data, 0, sizeof(struct login_s));
	make_login_data(login_data,&(pc_info->passenger_info));
	//	login_data = (struct login_s*)login_data_list->login_data;
	send_login(login_data,0);  
	//	free(login_data_list->login_data);
	free(login_data);

}

int add_pc_to_allow_list(u_int32_t ip, char *ip_str,char *id,char *mac, char *login_time)
{
	char id_type[8] = "", auth_type[8] = "";
	if(strlen(id) == 11){
		strcpy(auth_type,"1020004");
		strcpy(id_type,"19");
	}else if(strlen(id) == 17){
		strcpy(auth_type,"1020002");
		strcpy(id_type,"81");
		int i = 0;
		for(;i < strlen(id);i++){
			id[i] = toupper(id[i]);
			mac[i] = toupper(mac[i]);
		}
	}else if(strlen(id) == 18){
		strcpy(auth_type,"1020005");
		strcpy(id_type,"2");
	}else 
		return 0;
	struct pc_t *pc_info = (struct pc_t *)malloc(sizeof(struct pc_t));
	memset(pc_info,0,sizeof(struct pc_t));
	pc_info->src_ip = ip;
	fill_passenger_info(&(pc_info->passenger_info),ip_str, mac,id_type,id,auth_type,login_time);
	//	list_add_head(&(pc_info->passenger_info), &pc_hash_list);
	pthread_t delay_true_info_ID;
	pthread_create(&delay_true_info_ID,NULL,(void *)Send_True_Info,(void*)pc_info);
	list_add_head(&(pc_info->head), &pc_hash_list);
	return 1;
}


struct pc_t *find_pc_in_list(u_int32_t ip)
{
	struct pc_t *pc_tmp, *n;

	list_for_each_entry_safe(pc_tmp, n, &pc_hash_list, head)
	{
		if (pc_tmp->src_ip == ip)
			return pc_tmp;
	}

	return NULL;
}

int deal_recv_msg(char *recv_msg,char *ip,char *id,char *mac)
{
	char *p = strtok(recv_msg,"&");
	while(p)
	{
		if(strstr(p,"ip="))
		{
			p += 3;
			strcpy(ip,p);
			if(!strlen(ip))
				return 1;
			//printf("ip : %s",ip);
		}
		else if(strstr(p,"mobile="))
		{
			p += 7;
			strcpy(id,p);
			if(!strlen(id))
				return 1;
			//printf(" id : %s",id);
		}
		else if(strstr(p,"mac="))
		{
			p += 4;
			strcpy(mac,p);
			if(!strlen(mac))
				return 1;
			//printf(" mac : %s\n",mac);
		}
		p = strtok(NULL,"&");
	}
	return 0;
}
void addNewIpAddrToList(char *recv_msg ,char *login_time)
{
	struct in_addr srcIp;
	char ip[16] = "";
	char id[20] = "";
	char mac[18] = "";
	if(deal_recv_msg(recv_msg,ip,id,mac))
		return;
	inet_aton(ip, &srcIp);
	struct pc_t *ip_info = NULL;
	ip_info = find_pc_in_list(srcIp.s_addr);
	if(!ip_info)
	{
		add_pc_to_allow_list(srcIp.s_addr, ip,id,mac,login_time);
#ifdef IPTABLES
		memset(cmd,0,100);
		sprintf(cmd,"sh ./allow_ip.sh %s ",ip);
		system(cmd);
#endif
	}
	return;
}
#if 0
void user_online_recv()
{
	int num = 0;
	int sockfd = 0;
	char recvmsg[200] = {'\0'}; /*  buffer for message */
	struct sockaddr_in server; /*  server's address information */
	struct sockaddr_in client; /*  client's address information */
	char time_str[30] = {'\0'};
	socklen_t sin_size;
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) 
	{
		/*  handle exception */
		perror("Creating socket failed.");
		exit(1);
	}
	bzero(&server,sizeof(server));
	server.sin_family=AF_INET;
	server.sin_port=htons(USR_ONLINE_PORT);
	server.sin_addr.s_addr = htonl (INADDR_ANY);
	if (bind(sockfd, (struct sockaddr *)&server, sizeof(struct sockaddr)) == -1) 
	{
		/*  handle exception */
		perror("Bind error.");
		exit(1);
	}
	while(1)
	{	
		memset(recvmsg, '\0',200);
		num = recvfrom(sockfd,recvmsg,sizeof(recvmsg),0,(struct sockaddr *)&client,&sin_size);
		if (num < 0)
		{
			perror("recvfrom error\n");
			continue;
		}
		printf("Received msg %s to add pc ip address\n",recvmsg);
		addNewIpAddrToList(recvmsg);
	}
	return;
}


void start_online_recv(void)
{
	int ret;
	pthread_t online_recv;
	ret = pthread_create(&online_recv,NULL,(void *)user_online_recv,NULL);
	if(ret != 0)
	{
		printf("create online_checked_thread failed!\n");
		return ;
	}
	return;
}
#endif

#define fifo_path "/boyi/by_fifo"

void get_phonenum(char *phonenum,char *response)
{
	char *p = strstr(response,"phoneNumber=");
	p += strlen("phoneNumber=");
	strncpy(phonenum,p,11);
	return;
}

void mac_check(char *mac,char *ip)
{
#if 0
	if(monitor_mode != 0 && atoi(check_mac) == 1)
	{
		char cmd[150] = "";
		char response[100] = "";
		int	server_port = atoi(certifi_port);
		sprintf(cmd,"curl -s --connect-timeout 1 -m 1 http://%s:%d/wifiCenter/checkMac?params=%s",certifi_ip,server_port,mac);
		check_curl(cmd,response,sizeof(response));
		if(strstr(response,"status=1") != NULL)
		{
			char phonenum[12] = "";
			get_phonenum(phonenum,response);
			send_real_login(ip,mac,phonenum);
		}
	}
	else if(monitor_mode == 0)
		send_real_login(ip,mac,mac);
	return;
#endif
}

void deal_dhcp_info(char *buff)
{
	char *p = NULL;
	char ip[16] = "";
	char mac[20] = "";
	char status[2] = "";
	p = strtok(buff,"&");
	while(p)
	{
		if(strstr(p,"ip=") != NULL)
		{
			p += 3;
			strcpy(ip,p);
		}
		else if(strstr(p,"mac=") != NULL)
		{
			p += 4;
			strcpy(mac,p);
		}
		else if(strstr(p,"status=") != NULL)
		{
			p += 7;
			strcpy(status,p);
		}
		p = strtok(NULL,"&");
	}
	if(!strlen(ip) || !strlen(mac) || !strlen(status))
		return;
	printf("ip == %s mac == %s status == %s\n",ip,mac,status);
	if(strncmp(status,"0",1) == 0)
		mac_check(mac,ip);
	//	else if(strncmp(status,"1",1) == 0)
	return;
}

void dhcp_info(void *arg)
{
	char buff[100] = "";
	int num = mkfifo(fifo_path,0666);
	if(num < 0)
	{
		perror("mkfifo");//fifo has been
	}
	int fd = open(fifo_path,O_RDWR);
	while(1)
	{
		memset(buff,'\0',sizeof(buff));
		if(read(fd,buff,sizeof(buff)) < 0)
		{
			printf("read error...\n");
			continue;
		}
		deal_dhcp_info(buff);
	}
	return ;
}

void start_fifo_info(void)
{
	pthread_t dhcp_thread;
	pthread_create(&dhcp_thread,NULL,(void *)dhcp_info,NULL);
	return;
}

get_ip_mac(char *buf,char *ip_src,char *mac)
{
	char *p = strtok(buf," ");
	int i = 0;
	while(p)
	{
		if(i == 1)
		{
			strncpy(ip_src,p + 1,strlen(p) - 2);
		}
		else if(i == 3)
			strcpy(mac,p);
		p = strtok(NULL," ");
		i++;
	}
	return;
}

#if 0
void arp_info(void *arg)
{
	char buf[100] = "";
	FILE *ptr;
	int i = 0;
	char ip[20] = "",mac[20] = "";
	struct in_addr srcIp;
	struct pc_t *ip_info = NULL;
	while(1)
	{
		if((ptr = popen("arp -n","r")) != NULL)
		{
			while(fgets(buf,99,ptr))
			{
				get_ip_mac(buf,ip,mac);
				printf(" %s %s\n",ip,mac);
				inet_aton(ip, &srcIp);
				ip_info = find_pc_in_list(srcIp.s_addr);
				if(!ip_info)
					add_pc_to_allow_list(srcIp.s_addr, ip,mac,mac);
				memset(buf,0,sizeof(buf));
				memset(ip,0,sizeof(ip));
				memset(mac,0,sizeof(mac));
			}
		}
		pclose(ptr);
		sleep(10);
	}
	return ;
}

void start_arp_info()
{
	pthread_t arp_thread;
	pthread_create(&arp_thread,NULL,(void *)arp_info,NULL);
	return;
}
#endif
int make_url_post_data(struct url_post_s *data,struct panssenger_info * panssenger_info ,u_int32_t ip, u_int16_t port)
{

	time_t time_now = time(0);
	struct tm *t = localtime(&time_now);
	int l_port = 0;
	struct panssenger_info * info = panssenger_info;
	char time_n[20] = "";
	char dest_ip4[16] = "";
	char lan_port[8] = "";
	char dest_port[16] = "";
	strcpy(dest_ip4,inet_ntoa(*(struct in_addr*)&(ip)));
	srand((unsigned)time(NULL)); 
	l_port = atoi(info->source_startport4) + (rand()%200);

	sprintf(lan_port,"%d",l_port);
	sprintf(dest_port,"%d",port);
	data->version = my_strdup(info->version);
	data->event_type = my_strdup("43");
	data->doc_version= my_strdup(info->doc_version);
	sprintf(time_n,"%04d-%02d-%02d %02d:%02d:%02d",
			t->tm_year+1900, t->tm_mon+1,t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
	data->log_time = my_strdup(time_n);
	data->session_id = my_strdup(info->session_id);
	data->netserver_type = my_strdup("01");
	data->lan_ip = my_strdup(info->lan_ip);

	data->lan_port = my_strdup(lan_port);
	data->source_ip4 = my_strdup(info->source_ip4);
	data->source_ip6 = my_strdup(" ");
	data->source_startport4 = my_strdup(info->source_startport4);
	data->source_endport4 = my_strdup(info->source_endport4);
	data->source_startport6 = my_strdup(" ");
	data->source_endport6 = my_strdup(" ");
	data->destination_ip4 = my_strdup(dest_ip4);
	data->destination_ip6 = my_strdup("");

	data->destination_port4 = my_strdup(dest_port);
	data->destination_port6 = my_strdup("");

	data->mac = my_strdup(info->mac);
	data->location_code = my_strdup(info->location_code);
	data->apid = my_strdup(info->apid);
	data->longitude = my_strdup(info->longitude);
	data->latitude = my_strdup(info->latitude);
	data->apmac = my_strdup(info->apmac);
#ifdef PAIBO4_3_1
	data->source = my_strdup(info->source);
	data->plastersign = my_strdup(info->plastersign);
#endif 
	return 1;

}

int send_url_post_data(struct url_post_s *info)
{
	char msg[SEND_BUFF_SIZE]="";
	struct url_post_s *data = info;
	struct server_ip_list *temp=center_ip;
//	printf(" url ip == %s \n",temp->ip);
	while(temp)
	{
		build_send_msg(msg, (char **)data, sizeof(*data)/(sizeof(char *)));
		sendUDPmsg(temp->ip, SERVER_UDP_PORT, msg);
		//sendUDPmsg("192.168.0.102", SERVER_UDP_PORT, msg);
		memset(msg,0,SEND_BUFF_SIZE);
		temp=temp->next;
	}
	free_sent_data((char **)data, sizeof(*data)/(sizeof(char *)));
	return 1;

}



void deal_user_info(char *read_file,int type)
{
	char *p = NULL;
	int i = 0;
	p = strstr(read_file,"ip_type=");
	if(p)
	{
		char ip_type[2] = {'\0'};
		p += 8;
		strncpy(ip_type,p,1);

		if(strlen(ip_type) == 0)
			return;
		p = strstr(read_file,"ip=");
		if(p)
		{
			i = 0;
			char ip[16] = {'\0'};
			p += 3;
			while(i<16)
			{
				if(*p==10)
					break;
				strncpy(&ip[i],p,1);
				i++;
				p++;
			}

			if(strlen(ip) == 0)
				return;
			p = strstr(read_file,"usr_mac=");
			if(p)
			{
				char mac[18] = {'\0'};
				p += 8;
				strncpy(mac,p,17);

				if(strlen(mac) == 0)
					return;
				p = strstr(read_file,"onoff_flag=");
				if(p)
				{
					char onoff_flag[1] = {'\0'};
					p += 11;
					if(*p==11)
						return;
					strncpy(onoff_flag,p,1);

					if(strlen(onoff_flag) == 0)
						return;
					p = strstr(read_file,"onoff_time=");
					if(p)
					{
						i = 0;
						char onoff_time[12] = {'\0'};
						p += 11;
						while(i<12)
						{
							if(*p==10)
								break;
							strncpy(&onoff_time[i],p,1);
							i++;
							p++;
						}
						time_t time_now = atol(onoff_time);
						struct tm tm;
						localtime_r(&time_now, &tm);
						char time_str[64]="";
						sprintf(time_str,"%d-%02d-%02d %02d:%02d:%02d", 1900+tm.tm_year, tm.tm_mon+1, tm.tm_mday,tm.tm_hour,tm.tm_min, tm.tm_sec);

						if(strlen(time_str) == 0)
							return;
						char data[200] = {'\0'};
						//	sprintf(data,"mac=%s&ip=%s&mobile=%s&status=%d&time=%s",
						//mac,ip,phone_num,type,time_str);
						sprintf(data,"ip=%s&mobile=%s&mac=%s",\
								ip,mac,mac);
						//printf("infodata == %s\n",data);
						if(type == 1)						
						{
							//printf("%s\n",time_str);
							addNewIpAddrToList(data,time_str);
						}
						if(type == 0)
						{
							struct pc_t *pc_tmp, *n;
							int i = 0;
							char mac_t[20] = "";
							for(;i < strlen(mac);i++){
								mac[i] = toupper(mac[i]);
							}
							make_mac_add_colon(mac,mac_t);
							list_for_each_entry_safe(pc_tmp, n, &pc_hash_list, head)
							{
								if(strcasestr(pc_tmp->passenger_info.mac,mac_t))
								{
									remove_pc_from_allow_list(pc_tmp,time_str);
								}
								//printf("remove pc list on checked!\n");
							}
						}
					}
				}
			}
		}
	}
	return;
}

void *file_info_deal()
{
	printf("------------start inotify file-----------\n");

	//char* boyi_app_file = "/tmp/audit/";
	DIR *dp;
	struct dirent *dirp;
	char path_file[256] = {'\0'};
	FILE *fp = NULL;
	char read_file[500] ={'\0'};
	char cmd_mv[128] = {'\0'};
	char *p = NULL;
	int type = 0;
	char file_buf[32] = "";
	char boyi_app_file[32] = "";
	executeCMD("lsap --info_path", file_buf);
	strncpy(boyi_app_file, file_buf,strlen(file_buf)-1);
	while(1)
	{
		//printf("open file ==%s \n",boyi_app_file);

		if((dp = opendir(boyi_app_file)) == NULL)
		{
			printf("open dir faied");

			sleep(3);
			continue;
		}
		while((dirp = readdir(dp)) != NULL)
		{
			if(strstr(dirp->d_name,".info") == NULL || strstr(dirp->d_name,".swx") != NULL || strstr(dirp->d_name,".swp") !=NULL \
					|| strcmp(dirp->d_name, ".") == 0 || strcmp(dirp->d_name, "..") == 0)
				continue;

			sprintf(path_file, "%s/%s", boyi_app_file, dirp->d_name);
			//printf("info path == %s \n",path_file);

			fp = fopen(path_file,"r");
			if(fp == NULL)
			{
				perror("Open file path");
				continue ;
			}
			memset(read_file,0,sizeof(read_file));
			fread(read_file,sizeof(read_file),1,fp);

			p = strstr(dirp->d_name,"_");
			if(p)
			{
				p++;
				if(strncmp(p,"1",1) == 0)
				{
					type = 1;
				}
				else if(strncmp(p,"0",1) == 0)
				{
					type = 0;
				}
				else
					continue ;
				deal_user_info(read_file,type);

			}

			//sprintf(cmd_mv, "rm %s -rf", path_file);
			//system(cmd_mv);
			unlink(path_file);
			memset(path_file, 0, sizeof(path_file));
			//memset(cmd_mv, 0, sizeof(cmd_mv));
		}
		closedir(dp);
		sleep(1);
	}
}

void start_file_info_deal()
{
	int ret;
	pthread_t file_info_thread;
	ret = pthread_create(&file_info_thread,NULL,(void *)file_info_deal,NULL);
	if(ret != 0)
	{
		printf("create file_info_deal failed!\n");
		return ;
	}
	return;

}

void send_heartbeat()
{
	char buffer[24] = "";
	int i = 0;
	for(;i<24;i++)
	{
		buffer[i] = toupper(ap_id[i]);
	}
	struct sockaddr_in  server_address;
	int sockc = socket(AF_INET,SOCK_DGRAM,0);
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = inet_addr(center_ip->ip);
	//server_address.sin_addr.s_addr = inet_addr("192.168.0.102");
	server_address.sin_port = htons(18065);
	while(1)
	{
		sendto(sockc,buffer,strlen(buffer),0,(struct sockaddr*)&server_address,24);
		//printf("ip = %s\n",center_ip->ip);
		//printf("heart = %s\n",buffer);
		sleep(60);
	}

}

void start_heartbeat()
{
	int ret;
	pthread_t heartbeat_thread;
	ret = pthread_create(&heartbeat_thread,NULL,(void *)send_heartbeat,NULL);
	if(ret != 0)
	{
		printf("create file_info_deal failed!\n");
	}

}

