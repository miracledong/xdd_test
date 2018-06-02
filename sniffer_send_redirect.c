#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <sys/time.h>
#include "send_packet.h"
struct psuedohdr  {
  struct in_addr source_address;
  struct in_addr dest_address;
  unsigned char place_holder;
  unsigned char protocol;
  unsigned short length;
} psuedohdr;


static unsigned short
in_cksum (unsigned short *ptr, int nbytes)
{
  register long sum;/* assumes long == 32 bits */
  u_short oddbyte;
  register u_short answer;/* assumes u_short == 16 bits */
  /*
   *     Our algorithm is simple, using a 32-bit accumulator (sum),
   *     we add sequential 16-bit words to it, and at the end, fold back
   *     all the carry bits from the top 16 bits into the lower 16 bits.
   * */

  sum = 0;
  while (nbytes > 1) {
      sum += *ptr++;
      nbytes -= 2;
    }
  /* mop up an odd byte, if necessary */ if (nbytes == 1) {
      oddbyte = 0;/* make sure top half is zero */
      *((u_char *) & oddbyte) = *(u_char *) ptr;/* one byte only */
      sum += oddbyte;
    }

  /*
   * Add back carry outs from top 16 bits to low 16 bits.
   * */

  sum = (sum >> 16) + (sum & 0xffff);/* add high-16 to low-16 */
  sum += (sum >> 16);/* add carry */
  answer = ~sum;/* ones-complement, then truncate to 16 bits */
  return (answer);
}


unsigned short trans_check(unsigned char proto,
		                   char *packet,
						   int length,
						   struct in_addr source_address,
						   struct in_addr dest_address)
{
  char *psuedo_packet;
  unsigned short answer;

  psuedohdr.protocol = proto;
  psuedohdr.length = htons(length);
  psuedohdr.place_holder = 0;

  psuedohdr.source_address = source_address;
  psuedohdr.dest_address = dest_address;

  if((psuedo_packet = (char *)malloc(sizeof(psuedohdr) + length)) == NULL)  {
      perror("malloc");
      return 0;
    }

  memcpy(psuedo_packet,&psuedohdr,sizeof(psuedohdr));
  memcpy((psuedo_packet + sizeof(psuedohdr)), packet,length);

  answer = (unsigned short)in_cksum((unsigned short *)psuedo_packet, (length + sizeof(psuedohdr)));
  free(psuedo_packet);
  return answer;
}



int sniffer_send_redirect (char * payload, char *capurl)
{
	struct iphdr *iph = NULL;
	struct tcphdr *tcp = NULL;
	char *data = NULL;
	char *p_indata = NULL;
	char *p_outdata = NULL;
	struct in_addr saddr, daddr;
	char buf_redirect[1024] = "";
	__u32 old_seq;
	unsigned short old_port;
	int data_len = 0;
	int org_len = 0;
	int redirect_flag = 0;
	int status= 0;
	int tcp_doff = 0;
	struct timeval tv;
	char loc[20] = {'\0'};
	char time_str[64] = {'\0'};
	memset (buf_redirect, 0, sizeof(buf_redirect));
	p_indata = payload +14;
	struct ether_header *etherhdr;
	etherhdr = (struct ether_header *)payload;
#if 0
	if( ntohs(etherhdr->ether_type) == ETHERTYPE_VLAN){//for vlan
		p_indata+=4;
	}
#endif
	iph = (struct iphdr *)p_indata;
	tcp = (struct tcphdr *)(p_indata + (iph->ihl<<2));
	data = (char *)(p_indata + iph->ihl * 4 + tcp->doff * 4 );
	data_len= htons(iph->tot_len);
	org_len = data_len - iph->ihl * 4 - tcp->doff * 4;
	{

		if(strstr(capurl,"http://") || strstr(capurl,"https://"))
			memcpy(loc,"Location: ", sizeof("Location: "));
		else
			memcpy(loc,"Location: http://", sizeof("Location: http://"));

		sprintf (buf_redirect, \ 
				"HTTP/1.1 302 Moved Temporarily\r\n%s\r\n%s\r\n%s\r\n%s%s%s\r\n\r\n",
				"Content-Length: 0",
				"Pragma: no-cache",
				"Cache-Control: private, max-age=0, no-cache",
				"",
				loc,
				capurl);

//		printf("***%s***\n", buf_redirect);
		redirect_flag = 1; 
	}

	if (redirect_flag){
		p_outdata = p_indata;
		memset (p_outdata + iph->ihl * 4 + tcp->doff * 4, 0, org_len);

		tcp->doff = 5;
		tcp_doff = tcp->doff; 
		memcpy (p_outdata + iph->ihl * 4 + tcp->doff * 4, buf_redirect, strlen (buf_redirect));

		data_len = strlen (buf_redirect) + iph->ihl * 4 + tcp->doff * 4;

		iph = (struct iphdr *)p_outdata;
		tcp = (struct tcphdr *)(p_outdata + (iph->ihl<<2));
		data = (char *)(p_outdata + iph->ihl * 4 + tcp->doff * 4);

		saddr.s_addr = iph->saddr;
		daddr.s_addr = iph->daddr;
		iph->saddr = daddr.s_addr;
		iph->daddr = saddr.s_addr;


		iph->tot_len = htons (data_len);
		iph->check = 0;
		iph->check = in_cksum((unsigned short *)iph, iph->ihl * 4); 



		memset ((char *)tcp+12, 0, 2);
		tcp->res1 = 0;
		tcp->doff = tcp_doff; //set the header len(options may set it other than 5)
		tcp->psh = 1; 
		tcp->ack = 1;
		tcp->fin = 1;

		old_seq = tcp->seq;
		tcp->seq= ntohl (htonl (tcp->ack_seq));
		tcp->ack_seq = ntohl (htonl (old_seq) + org_len );

		old_port = tcp->dest;
		tcp->dest = tcp->source;
		tcp->source = old_port;

		tcp->check = 0;
		tcp->check = trans_check(IPPROTO_TCP, (char *)tcp, data_len - sizeof(struct iphdr), daddr, saddr);

		SendPacketWithDestMac(p_outdata, data_len, payload+6);

		return status;
	}       

	return status;
}
