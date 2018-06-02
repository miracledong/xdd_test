#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h>    //For standard things
#include<stdlib.h>    //malloc
#include<string.h>    //strlen
#include<netinet/ip6.h>
#include<netinet/ip_icmp.h>    //Provides declarations for icmp header
#include<netinet/udp.h>    //Provides declarations for udp header
#include<netinet/tcp.h>    //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<netinet/if_ether.h>    //For ETH_P_ALL
#include<net/ethernet.h>    //For ether_header
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include<unistd.h>
#include "analysis_pack.h"
#include "sniffer_def.h"
#include "sniffer_util.h"
#include "ip_list.h"
#include "session.h"
#define __USE_GNU
//#include "block.h"
//# ADD_MAC
#define ADD_MAC 1
//#endif
extern char GlbRedirectUrl[256];
extern char androidUrl[256];
extern char appleUrl[256];
extern char windowUrl[256];
extern int monitor_mode;
extern char loc_ip[16];
extern char mac_list[300];
extern struct ip_list *head;
struct list_head  pc_hash_list;
char add_mac_check[24] = {'\0'};
//static char check_mun[2] = {'\0'}; 
//static char repeat_mun[2] = {'\0'};
static int updateOffset(uint8_t isIPv4, const char *data_p)
{
	const struct tcphdr *tcp;
	int payload_offset;

#ifdef UFD_DEBUG
	printf("isIPv4<%d>\n", isIPv4);
#endif

	if (isIPv4)
	{
		const struct iphdr *iph;

		iph = (const struct iphdr *)data_p;
		tcp = (const struct tcphdr *)(data_p + (iph->ihl<<2)); //tcp head
		payload_offset = ((iph->ihl)<<2) + (tcp->doff<<2);

#ifdef UFD_DEBUG
		printf("offset<%d>\n", payload_offset);
#endif
		return payload_offset;
	}
	else
	{
		const struct ip6_hdr *ip6h;
		const struct ip6_ext *ip_ext_p;
		uint8_t nextHdr;
		int count = 8;

		ip6h = (const struct ip6_hdr *)data_p;
		nextHdr = ip6h->ip6_nxt;
		ip_ext_p = (const struct ip6_ext *)(ip6h + 1);
		payload_offset = sizeof(struct ip6_hdr);

		do
		{
			if ( nextHdr == IPPROTO_TCP )
			{
				tcp = (struct tcphdr *)ip_ext_p;
				payload_offset += tcp->doff << 2;

#ifdef UFD_DEBUG
				printf("offset<%d>\n", payload_offset);
#endif
				return payload_offset;
			}

			payload_offset += (ip_ext_p->ip6e_len + 1) << 3;
			nextHdr = ip_ext_p->ip6e_nxt;
			ip_ext_p = (struct ip6_ext *)(data_p + payload_offset);
			count--; /* at most 8 extension headers */
		} while(count);
	}

	return -1;
}

#define   u_int32_t unsigned long
extern unsigned long br0IP;
extern unsigned long mask_num;
extern unsigned long net_num;

int is_tcp_packet;
int is_udp_packet;
//	PURL current;
int payload_offset;
unsigned char* tmpbuf;
struct ethhdr *tmpethhdr;
uint8_t isIPv4;
int data_len;
static unsigned long int seq;
struct iphdr *iph;
struct udphdr *udp;
struct tcphdr *tcph;
char ip_str[16];
char mac[20];
char sou_ip[16] = {'\0'};
char des_ip[16] = {'\0'};
struct pc_t *ip_info;
struct pc_t * find_pc_in_list_by_mac(char *mac)
{
	struct pc_t *pc_tmp, *n;

	list_for_each_entry_safe(pc_tmp, n, &pc_hash_list, head)
	{
		//		printf("passenger_info.mac == %s--------mac == %s\n",pc_tmp->passenger_info.mac,mac);
		if(strcasestr(pc_tmp->passenger_info.mac,mac))
			return pc_tmp;
	}

	return NULL;
}
void analysis_pack(unsigned char* buffer, int size)
{
	tmpbuf = buffer + sizeof(struct ethhdr); //skip mac head
	tmpethhdr = (struct ethhdr *)buffer; //mac head
	//	static i = 0;
	//printf("%s --- %d\n", __FILE__,__LINE__);
	char *match = NULL,*data = NULL;
	//printf("-----%04x\n",ntohs(tmpethhdr->h_proto)); 
	//if (ntohs(tmpethhdr->h_proto) != 0x0800) 
	//	return;
	//char mac_check_t[20];
	//sprintf(mac_check_t,"%02x-%02x-%02x-%02x-%02x-%02x", tmpethhdr->h_source[0] , tmpethhdr->h_source[1] , tmpethhdr->h_source[2] , tmpethhdr->h_source[3] , tmpethhdr->h_source[4] , tmpethhdr->h_source[5]);
	//printf("src mac_t == %s \n",mac_check_t);
	if (ntohs(tmpethhdr->h_proto) == 0x8100) //VLAN
	{
			//printf("vlan---%04x\n",ntohs(tmpethhdr->h_proto)); 
			tmpbuf += 4;
	}
	data = tmpbuf;
	//printf("%s --- %d\n", __FILE__,__LINE__);
	//Get the IP Header part of this packet
	iph = (struct iphdr*)tmpbuf;  //IP head
	isIPv4 = (iph->version == 4)?1:0;
	payload_offset = updateOffset(isIPv4, tmpbuf);
	if(payload_offset < 0)
		return;
	//match = tmpbuf + payload_offset;  //skip ip & tcp head
	//char sou_ip[16] = {'\0'};
	//char des_ip[16] = {'\0'};
	if(iph->protocol == 6)		//TCP packet
	{
		tcph = (struct tcphdr *)(((char*)iph) + (iph->ihl<<2));
		//		if(tcph && tcph->dest == htons(443))
		//			return;
		//	strcpy(sou_ip,inet_ntoa(*(struct in_addr*)&(iph->saddr)));
		//	strcpy(des_ip,inet_ntoa(*(struct in_addr*)&(iph->daddr)));
		data_len = htons(iph->tot_len)-(((iph->ihl)<<2) + (tcph->doff<<2));
		if(data_len <= 0)
			return;
	}
#if 0
	else if(iph->protocol == 17)//UDP packet
	{
		is_udp_packet = 1;
		udp = (struct udphdr *)(((char*)iph) + (iph->ihl<<2));
		if(udp && udp->dest == htons(53))
			return;
		data = ((const unsigned char*)udp) + sizeof(struct udphdr);
		data_len = ntohs(iph->tot_len)-(iph->ihl)*4-sizeof(struct udphdr);
	}
#endif
	else
	{
		return;
	}
	//char IPdotdec[20] = "";
	//inet_ntop(AF_INET, (void *)&(iph->saddr), IPdotdec, 16);
	//printf("src ip == %s \n",IPdotdec);
	//char IPdotdec1[20] = "";
	//inet_ntop(AF_INET, (void *)&(iph->daddr), IPdotdec1, 16);
	//printf("dst ip == %s \n",IPdotdec1);
	//if((iph->saddr & mask_num) != net_num || (iph->daddr & mask_num) == net_num) 
	//	return;
	//if(iph->saddr == br0IP || iph->saddr == inet_addr("192.168.1.1"))
	//	return;
	match = tmpbuf + payload_offset;
	struct pc_t *ip_info = NULL;
	char mac_check[18] = "";
	sprintf(mac_check,"%02x-%02x-%02x-%02x-%02x-%02x", tmpethhdr->h_source[0] , tmpethhdr->h_source[1] , tmpethhdr->h_source[2] , tmpethhdr->h_source[3] , tmpethhdr->h_source[4] , tmpethhdr->h_source[5]);
	//printf("src mac == %s \n",mac_check);
	//if ((ip_info = find_pc_in_list_by_mac(mac_check)) != NULL && ip_info->src_ip == iph->saddr)
	if ((ip_info = find_pc_in_list_by_mac(mac_check)) != NULL)
	{
		//Update the online time
		///ip_info->passenger_info.last_visit_time = time(0);
		//deal TCP packet IPPROTO_TCP == 6
		//weixin
#if 1
		if((tcph->dest == htons(8080) || tcph->dest == htons(80) || tcph->dest == htons(443)) && data_len > 20 && data_len == htonl(*(int*)match) \
				&& *(int *)(match + 4) == htonl(0x100001) && *(short *)(match + 8) == 0x0 && (unsigned char)match[16] == 0xbf)
		{
			if(get_weixin_login(match,data_len,&(ip_info->passenger_info)))
				return;
		}
		handle_tcp(tcph,data_len,&(ip_info->passenger_info));
#endif

		//session
		struct session_t *session = NULL;
		session = do_session_filter(data, 0);
		//	struct tcphdr* tcp = (struct tcphdr*)((char*)iph+(iph->ihl<<2));
		//	int data_len = htons(iph->tot_len) - iph->ihl*4 - tcp->doff*4;
		if(session == NULL)
			return;
		if(session->ses_st == SES_FIN)
		{
			//	char session_dst_ip[20] = "";
			//	char session_dst_port[20] = "";
			//	struct tcphdr* tcp_des_t = (struct tcphdr*)((char*)iph+(iph->ihl<<2));
			//	sprintf(session_dst_port,"%d",htons(tcp_des_t->dest));
			//	inet_ntop(AF_INET, (void *)&(iph->daddr),session_dst_ip, 16);
			if(session->url_data)
			{
				struct url_s *url = (struct url_s *)session->url_data;
				if(url && url->url)
					handle_app(data,session, &(ip_info->passenger_info));

#if 1

				if(strstr(match,"GET") || strstr(match, "POST"))
				{
					static unsigned int iTimeCount = 0;
					struct tcphdr* tcp = (struct tcphdr*)((char*)iph+(iph->ihl<<2));
					if(time((time_t*)NULL) - iTimeCount > 1)
					{
						iTimeCount = time(NULL);
						struct url_post_s *urldata = NULL;
						urldata=malloc(sizeof(struct url_post_s));
						make_url_post_data(urldata,&(ip_info->passenger_info),iph->daddr,tcp->dest);
						send_url_post_data(urldata);
						free(urldata);
					}
				}
#endif

			}
			set_session_status(session);
		}
	}
	else if(monitor_mode == 0)
	{
		char IPdotdec[20] = "";
		inet_ntop(AF_INET, (void *)&(iph->saddr), IPdotdec, 16);
		//add_pc_to_allow_list(iph->saddr,IPdotdec,mac_check,mac_check);	
	}
	return;
}
