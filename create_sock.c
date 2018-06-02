#define _GNU_SOURCE //for strcasestr
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <net/if.h>
#include <errno.h>
#include <features.h>
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include <sys/stat.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/sockios.h>

#include "create_sock.h"

int raw_socket(int ifindex)
{
    int fd;
    struct sockaddr_ll sock;

    memset(&sock, 0, sizeof(sock));

    //if ((fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
if ((fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        printf("socket call failed: errno=%d", errno);
        return -1;
    }
/*
    sock.sll_family = AF_PACKET;
    sock.sll_protocol = htons(ETH_P_IP);
    sock.sll_ifindex = ifindex;
    if (bind(fd, (struct sockaddr *)&sock, sizeof(sock)) < 0) {
        printf("bind call failed: errno=%d", errno);
//        close(fd);
//        return -1;
    }
*/
    //printf("fd = %d\n", fd);
    return fd;
}

void adjust_sock_buff_size()
{
    int sock_raw;
    int z;
    int sndbuf = 0;
    int revbuf = 0;
    socklen_t optlen;

    sock_raw = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    optlen = sizeof(revbuf);

    z = getsockopt(sock_raw, SOL_SOCKET, SO_RCVBUF, &revbuf, &optlen);
    //printf("z = %d, revbuf = %d\n", z, revbuf);

    sndbuf = 1024 * 1024;
    z = setsockopt(sock_raw, SOL_SOCKET, SO_RCVBUF, (char *)&sndbuf, sizeof(sndbuf));        

    z = getsockopt(sock_raw, SOL_SOCKET, SO_RCVBUF, &revbuf, &optlen);
   // printf("z = %d, revbuf = %d\n", z, revbuf);

}

int create_socket(char* ifrname)
{
	int fd;
	struct ifreq ifr;
	struct in_addr temp_addr;
	struct sockaddr_ll fromaddr;
	unsigned char src_mac[ETH_ALEN]={0};
	if (ifrname == NULL)
		return -1;

//	adjust_sock_buff_size();

	//if ((fd = socket(AF_PACKET, SOCK_RAW, (ETH_P_ALL))) < 0)
//	if ((fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)
	if ((fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		return -1;
	bzero(&fromaddr,sizeof(fromaddr));
	bzero(&ifr,sizeof(ifr));
	strcpy(ifr.ifr_name, ifrname);

	// if (ioctl(fd, SIOCGIFHWADDR, &ifr) != 0)
	if (ioctl(fd, SIOCGIFINDEX, &ifr) != 0)
		return -1;
	fromaddr.sll_ifindex = ifr.ifr_ifindex;
	// close(fd);

	// fd = raw_socket(ifr.ifr_ifindex);
	if(-1 == ioctl(fd,SIOCGIFHWADDR,&ifr)){

		perror("get dev MAC addr error:");

		exit(1);
	}
	memcpy(src_mac,ifr.ifr_hwaddr.sa_data,ETH_ALEN);
	fromaddr.sll_family = PF_PACKET;
	fromaddr.sll_protocol=htons(ETH_P_ALL);
//	fromaddr.sll_hatype=ARPHRD_ETHER;
	fromaddr.sll_pkttype=PACKET_OTHERHOST;
//	fromaddr.sll_pkttype=PACKET_HOST;
	fromaddr.sll_halen=ETH_ALEN;
	memcpy(fromaddr.sll_addr,src_mac,ETH_ALEN);
	bind(fd,(struct sockaddr*)&fromaddr,sizeof(struct sockaddr));
#if 0
	if (-1 == ioctl(fd, SIOCGIFFLAGS, &ifr)) 
	{
		perror("ioctl");
		close(fd);
		exit(-1);
	}
	ifr.ifr_flags |= IFF_PROMISC;
	if(-1 == ioctl(fd, SIOCSIFFLAGS, &ifr)) //将标志位设置写入
	{
		perror("ioctl");
		close(fd);
		exit(-1);
	}
#endif
	return fd;
}
