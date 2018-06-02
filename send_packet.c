#include <stdio.h>
#include<malloc.h>
#include<string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <sys/time.h>
#include <stdlib.h>
#include <errno.h>
extern char network_card[10];

static int sockfd;
static char src_mac[ETH_ALEN];
static unsigned char dest_mac[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

char*  get_def_gw_ifname(char* gw_ifname, char *gw_ip)
{
	FILE *fp;
	char buf[256];
	char *p;
	fp = popen("/sbin/route -n", "r");
	if(fp == NULL)
		return NULL; 

	while(fgets(buf, sizeof(buf), fp ))
	{
		if(strstr(buf, "UG"))   {//0.0.0.0         172.16.10.254   0.0.0.0         UG    0      0        0 atm0
			p = strtok((char *)buf, " ");//skip 0.0.0.0
			p = strtok(NULL, " ");//locate default gw
			strcpy(gw_ip, p);
			p = strtok(NULL, " ");//locate default gw
			p = strtok(NULL, " ");//locate default gw

			p = strtok(NULL, " ");//locate default gw
			p = strtok(NULL, " ");//locate default gw
			p = strtok(NULL, " ");//locate default gw
			p = strtok(NULL, " ");//locate default gw
			memcpy(gw_ifname, p, strlen(p)-1);

			pclose(fp);
			return gw_ifname;

		}
		memset(buf, 0, sizeof(buf));
	}
	pclose(fp);
	return NULL;
}

static int initSocketAddress(struct sockaddr_ll* socket_address, char *ifName)
{
    struct ifreq ifr;
    int i;

    /* RAW communication */
    socket_address->sll_family = AF_PACKET; /* TX */
    socket_address->sll_protocol = 0; /* BIND */ /* FIXME: htons(ETH_P_ALL) ??? */

    memset(&ifr, 0x00, sizeof(ifr));
    strncpy(ifr.ifr_name, ifName, sizeof(ifr.ifr_name));
    if(ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0)
    {
        printf("Fail to get ifindex\n");

	close(sockfd);
        return -1;
    }
    socket_address->sll_ifindex = ifr.ifr_ifindex; /* BIND, TX */

    socket_address->sll_hatype = 0; /* RX */
    socket_address->sll_pkttype = PACKET_OTHERHOST; /* RX */

    socket_address->sll_halen = ETH_ALEN; /* TX */

    /* MAC */
    for(i = 0; i < ETH_ALEN; i++)
    {
        socket_address->sll_addr[i] = dest_mac[i]; /* TX */
    }
    socket_address->sll_addr[6] = 0x00;/*not used*/
    socket_address->sll_addr[7] = 0x00;/*not used*/

    /* Get source MAC of the Interface we want to bind to */
    memset(&ifr, 0x00, sizeof(ifr));
    strncpy(ifr.ifr_name, ifName, sizeof(ifr.ifr_name));
	if(ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0)
	{
		printf("Fail to get hw addr\n");
		close(sockfd);
		return -1;
	}

    for(i = 0; i < ETH_ALEN; i++)
    {
        src_mac[i] = (unsigned char)ifr.ifr_hwaddr.sa_data[i];
    }

   // printf("Binding to %s: ifindex <%d>, protocol <0x%04X>...\n",
          // ifName, socket_address->sll_ifindex, socket_address->sll_protocol);

    /* Bind to Interface */
    if(bind(sockfd, (struct sockaddr*)socket_address, sizeof(struct sockaddr_ll)) < 0)
    {
        printf("Binding error\n");
	close(sockfd);
        return -1;
    }

   // printf("Done!\n");

    return 0;
}


static int flag = 0;

int SendPacketWithDestMac(char *data, int len,  char *dmac)
{
	int ret;
	struct timeval tv;
	static char *ifName = network_card;
	static struct sockaddr_ll socket_address;
	memcpy(dest_mac, dmac, sizeof(dest_mac));
	struct ethhdr raw_eth_hdr;
	char tx_buf[1512] = {'\0'};
	if(!flag)
	{
		if((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
		{
			printf("ERROR: Could not open Raw Socket\n");
			return -1;
		}

		ret = initSocketAddress(&socket_address, ifName);
		if(ret != 0)
			return 0;
		flag = 1;
	}
	memset(&raw_eth_hdr,0,sizeof(struct ethhdr));
	memset(tx_buf,0,sizeof(tx_buf));

	int i;
	for (i=0; i<6; i++)
	{
		raw_eth_hdr.h_dest[i] = (u_char)dest_mac[i];
		raw_eth_hdr.h_source[i] = (u_char)src_mac[i];
	}
//	printf("\n the mac address is : %02x:%02x:%02x:%02x:%02x:%02x\n", dest_mac[0],dest_mac[1],dest_mac[2],dest_mac[3],dest_mac[4],dest_mac[5]);
//	printf("\n the src mac address is : %02x:%02x:%02x:%02x:%02x:%02x\n", src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]);
	raw_eth_hdr.h_proto = htons(0x0800);
	memcpy(tx_buf,&raw_eth_hdr,14);
	memcpy(tx_buf+sizeof(raw_eth_hdr),data,len);
	if ( sendto(sockfd, (void *)tx_buf, len+sizeof(raw_eth_hdr), 0, (struct sockaddr*)&socket_address, sizeof(socket_address)) < 0)
	{
		printf("\n sending data on Raw socket is failed %d\n",errno);
	}
//	close(sockfd);
	return 0;
}

int SendPacketWithDestMac_bak(char *data, int len,  char *dmac)
{
	int ret;
	struct timeval tv;
	char *ifName = network_card;
	struct sockaddr_ll socket_address;
	memcpy(dest_mac, dmac, sizeof(dest_mac));
	struct ethhdr raw_eth_hdr;
	char tx_buf[1512] = {'\0'};
	if((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
	{
		printf("ERROR: Could not open Raw Socket\n");
		return -1;
	}

	ret = initSocketAddress(&socket_address, ifName);
	if(ret != 0)
		return 0;
	memset(&raw_eth_hdr,0,sizeof(struct ethhdr));
	memset(tx_buf,0,sizeof(tx_buf));

	int i;
	for (i=0; i<6; i++)
	{
		raw_eth_hdr.h_dest[i] = (u_char)dest_mac[i];
		raw_eth_hdr.h_source[i] = (u_char)src_mac[i];
	}
//	printf("\n the mac address is : %02x:%02x:%02x:%02x:%02x:%02x\n", dest_mac[0],dest_mac[1],dest_mac[2],dest_mac[3],dest_mac[4],dest_mac[5]);
//	printf("\n the src mac address is : %02x:%02x:%02x:%02x:%02x:%02x\n", src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]);
	raw_eth_hdr.h_proto = htons(0x0800);
	memcpy(tx_buf,&raw_eth_hdr,14);
	memcpy(tx_buf+sizeof(raw_eth_hdr),data,len);
	if ( sendto(sockfd, (void *)tx_buf, len+sizeof(raw_eth_hdr), 0, (struct sockaddr*)&socket_address, sizeof(socket_address)) < 0)
	{
		printf("\n sending data on Raw socket is failed %d\n",errno);
	}
	close(sockfd);
	return 0;
}
