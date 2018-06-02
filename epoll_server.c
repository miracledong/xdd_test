#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h> 
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>    	//Provides declarations for icmp header
#include <netinet/udp.h>    		//Provides declarations for udp header
#include <netinet/tcp.h>    		//Provides declarations for tcp header
#include <netinet/ip.h>    			//Provides declarations for ip header
#include <netinet/if_ether.h>   	//For ETH_P_ALL
#include <net/ethernet.h>    		//For ether_header
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include <dirent.h>
#include <unistd.h>
#include "/home/edu/maipu/yanliang/libpcap-1.8.1/tmp/include/pcap.h"

#include "epoll_server.h"
#include "thread_process_function.h"
#include "create_sock.h"
#include "sniffer_data.h"
#include "filter.h"
/*线程池的线程数量*/
#define THREAD_MAX 100
/*监听端口*/
#define LISTEN_PORT 8000

#define SNF_BUF_SIZE 1518

#define BUFSIZE 1514
/*
   监听端口的数量,从LISTEN_PORT到LISTEN_PORT+LISTEN_MAX-1
   */
#define LISTEN_MAX 1
#define SERVER_IP "60.28.26.20"
extern char network_card[20];
extern char ap_mac[20];
extern char ap_mac_t[20];
extern char loc_ip[16];
extern int ap_mode;
//服务器参数
//static listen_info s_listens[LISTEN_MAX];
//线程池参数
static unsigned int s_thread_para[THREAD_MAX][9];//线程参数
static pthread_t s_tid[THREAD_MAX];//线程ID
pthread_mutex_t s_mutex[THREAD_MAX];//线程锁
//线程函数
struct sniffer_data snf_data_arry[SNF_ARRY_SIZE];
unsigned int packet_need_to_deal = 0;

//私有函数
static int init_thread_pool(void)
{
	int    i, rc;
	char *p;
	//初始化线程池参数
	for (i = 0; i < THREAD_MAX; i++)
	{
		s_thread_para[i][0] = 0;//设置线程占用标志为"空闲"
		s_thread_para[i][7] = i;//线程池索引
		p = (char *)malloc(SNF_BUF_SIZE);
		if(p == NULL)
			perror("malloc:");
		memset(p,0,SNF_BUF_SIZE);
		s_thread_para[i][8] = (int)p;	
		pthread_mutex_lock(s_mutex + i);//线程锁
		//创建线程池
		rc = pthread_create(s_tid + i, 0, (void *)thread_process_function, (void *)(s_thread_para[i]));
		if (0 != rc)
		{
			fprintf(stderr, "线程创建失败/n");
			return(-1);
		}
	}
	sleep(10);
	//成功返回
	return(0);
}

static int init_listen(char *ip4, int port, int max_link)
{
	//临时变量
	int            sock_listen4;
	struct sockaddr_in    addr4;
	unsigned int         optval;
	struct linger        optval1;

	//初始化数据结构
	bzero(&addr4, sizeof(addr4));
	inet_pton(AF_INET, ip4, &(addr4.sin_addr));
	addr4.sin_family = AF_INET;
	addr4.sin_port = htons(port);

	//创建SOCKET
	sock_listen4 = socket(AF_INET, SOCK_STREAM, 0);
	if (0 > sock_listen4) return(-1);

	//设置SO_REUSEADDR选项(服务器快速重起)
	optval = 0x1;
	setsockopt(sock_listen4, SOL_SOCKET, SO_REUSEADDR, &optval, 4);

	//设置SO_LINGER选项(防范CLOSE_WAIT挂住所有套接字)
	optval1.l_onoff = 1;
	optval1.l_linger = 60;
	setsockopt(sock_listen4, SOL_SOCKET, SO_LINGER, &optval1, sizeof(struct linger));

	if (0 > bind(sock_listen4, (struct sockaddr *)&addr4, sizeof(addr4)))
	{
		close(sock_listen4);
		return(-1);
	}

	if (0 > listen(sock_listen4, max_link))
	{
		close(sock_listen4);
		return(-1);
	}

	return(sock_listen4);
}
#if 0
void start_deal_package()
{
	struct sockaddr saddr;
	int saddr_size;
	unsigned int packet_index = 0;
	pthread_t thread;
	int sock_raw = create_socket(network_card);
	if (sock_raw < 0)
	{
		printf("create socket error %d\n",errno);
		return 1;
	}

	malloc_sniffer_buffer(snf_data_arry, SNF_ARRY_SIZE);
	pthread_create(&thread, NULL, sniffer_data_deal, NULL);
	saddr_size = sizeof saddr;
	while(1)
	{
		pthread_mutex_lock(&snf_data_arry[packet_index].mutex);
		snf_data_arry[packet_index].data_size = recvfrom(sock_raw, snf_data_arry[packet_index].buffer, SNF_BUF_SIZE - 1, 0, &saddr, (socklen_t*)&saddr_size);
		if(snf_data_arry[packet_index].data_size <= 0)
		{
			printf("----%s:%d %d %d---\n",__FILE__,__LINE__,snf_data_arry[packet_index].data_size,errno);
			pthread_mutex_unlock(&snf_data_arry[packet_index].mutex);
			continue;
		}
		packet_need_to_deal++;
		pthread_mutex_unlock(&snf_data_arry[packet_index].mutex);
		packet_index++;
		if (packet_index >= SNF_ARRY_SIZE)
			packet_index = 0;
	}
}
#endif
unsigned int pcap_packet_index = 0;
void ethernet_protocol_callback(unsigned char *argument,const struct pcap_pkthdr *packet_heaher,const unsigned char *packet_content)
{
	unsigned char *mac_string;				//
	struct ether_header *ethernet_protocol;
	unsigned short ethernet_type;			//以太网类型
	//char mac_buf[20] = "";
	ethernet_protocol = (struct ether_header *)packet_content;
	ethernet_type = ntohs(ethernet_protocol->ether_type);//获得以太网的类型

	//mac_string = (unsigned char *)ethernet_protocol->ether_shost;//获取源mac地址
	//mac_string = (unsigned char *)ethernet_protocol->ether_dhost;//获取目的mac
	//sprintf(mac_buf,"%02x-%02x-%02x-%02x-%02x-%02x",*(mac_string+0),*(mac_string+1),*(mac_string+2),
	//		*(mac_string+3),*(mac_string+4),*(mac_string+5));
	//printf("ethernet_type-----%04x\n",ethernet_type);

	//if(strcmp(mac_buf,ap_mac_t) != 0)
	//{
	//	usleep(10);
		if((ethernet_type == 0x0800)||(ethernet_type == 0x8100))
		{
//mutex_trylock:
//			if (pthread_mutex_trylock(&snf_data_arry[pcap_packet_index].mutex) == 0)
//			{	
				//printf("--------%s---------%d-------\n",__FILE__,__LINE__);
				usleep(1);
				memset(snf_data_arry[pcap_packet_index].buffer,'\0',SNF_BUF_SIZE);
				memcpy(snf_data_arry[pcap_packet_index].buffer,packet_content,packet_heaher->caplen); 
				snf_data_arry[pcap_packet_index].data_size = packet_heaher->caplen; 

				packet_need_to_deal++;
				//printf("packet to deal = %d\n",packet_need_to_deal);
//				pthread_mutex_unlock(&snf_data_arry[pcap_packet_index].mutex);
//			}
//			else
//			{
				pcap_packet_index++;
				//printf("pcap_index = %d\n",pcap_packet_index);
				if (pcap_packet_index >= SNF_ARRY_SIZE)
					pcap_packet_index = 0;
//				goto mutex_trylock;
//			}
//			pcap_packet_index++;
//			if (pcap_packet_index >= SNF_ARRY_SIZE)
//				pcap_packet_index = 0;

		}
//	}
	//mac_string = (unsigned char *)ethernet_protocol->ether_shost;//获取源mac地址
	//printf("Mac Source Address is %02x:%02x:%02x:%02x:%02x:%02x\n",*(mac_string+0),*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));
	//mac_string = (unsigned char *)ethernet_protocol->ether_dhost;//获取目的mac
	//printf("Mac Destination Address is %02x:%02x:%02x:%02x:%02x:%02x\n",*(mac_string+0),*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));
}
void start_deal_package()
{
	char error_content[PCAP_ERRBUF_SIZE];	//出错信息
	pcap_t * pcap_handle;
	unsigned char *mac_string;				//
	unsigned short ethernet_type;			//以太网类型
	//unsigned int net_ip;					//网络地址
	//unsigned int net_mask;					//子网掩码
	char dev_buf[16] = "";
	char net_interface_t[16] = "";					//接口名字
	executeCMD("lsap --devices", dev_buf);
	strncpy(net_interface_t,dev_buf,strlen(dev_buf)-1);
	char *net_interface = net_interface_t;					//接口名字
	printf("devices is %s\n",net_interface);
	//struct pcap_pkthdr protocol_header;
	//struct ether_header *ethernet_protocol;
	//struct bpf_program bpf_filter;
	//char bpf_filter_string[100] = "";
	pthread_t thread;

	malloc_sniffer_buffer(snf_data_arry, SNF_ARRY_SIZE);
	pthread_create(&thread, NULL, sniffer_data_deal, NULL);
	while(1)
	{
		pcap_handle = pcap_open_live(net_interface,BUFSIZE,1,0,error_content);//打开网络接口
	//	pcap_compile(pcap_handle,&bpf_filter,bpf_filter_string,0,0);//编译BPF过滤规则
	//	pcap_setfilter(pcap_handle,&bpf_filter);//设置过滤规则
		if (pcap_handle == NULL)
			printf("pacp_handle NULL");

		if (strlen(ap_mac_t))
		{
			printf("------------NAT-------------\n");
		
			if( pcap_setdirection(pcap_handle, PCAP_D_IN) == 0)//路由模式PCAP_D_OUT 为下行流量 PCAP_D_IN 为上行流量 并不适用所有平台
			{
				printf("pcap_setdirection success\n");
			}
		}
		else
		{
			printf("------------bridge-------------\n");
			if( pcap_setdirection(pcap_handle, PCAP_D_OUT) == 0)//桥模式PCAP_D_OUT 为上行流量 PCAP_D_IN 为下行流量 并不适用所有平台
			{
				printf("pcap_setdirection success\n");
			}

		}

#if 0
		printf("--------%s---------%d-------\n",__FILE__,__LINE__);
		if (pcap_compile(pcap_handle,&bpf_filter,bpf_filter_string,1,0) == 0)//编译BPF过滤规则
		{
			printf("pcap_compile success\n");
		}

		if(pcap_setfilter(pcap_handle,&bpf_filter) == 0)//设置过滤规则
		{
			printf("pcap_setfilter success\n");
		}
#endif


		if (pcap_datalink(pcap_handle) != DLT_EN10MB)
			return ;
		pcap_loop(pcap_handle,-1,ethernet_protocol_callback,snf_data_arry);
		pcap_close(pcap_handle);
		sleep(10);
	}
}
