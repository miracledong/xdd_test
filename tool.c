/* ************************************************************************
 *       Filename:  tool.c
 *    Description:  
 *        Version:  1.0
 *        Created:  2016年09月08日 15时58分23秒
 *       Revision:  none
 *       Compiler:  gcc
 *         Author:  YOUR NAME (), 
 *        Company:  
 * ************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
void write_to_file_t(char *path,char *mod,char *buff)
{
    FILE *fp;
    if((fp=fopen(path,mod))==NULL)
    {
		printf("open failed \n");
        return;
    }
    fwrite(buff,strlen(buff),1,fp);
    fclose(fp);
}
int readfile_get_mac(char *src_ip,char *mac)
{
	char buffer[200] = "";
	FILE *fp;
	fp = fopen("/proc/net/arp","r");
	if(fp == NULL)
	{
		perror("file not exists\n");
		return 0 ;	

	}
	while(fgets(buffer,sizeof(buffer),fp) != NULL)
	{
		char *pos = NULL;
		char ip[20] = "";
		pos = strstr(buffer," ");
		strncpy(ip,buffer,pos-buffer);
		int ret = strcmp(ip,src_ip);
		if(ret == 0)
		{
			pos = strstr(buffer,":");
			if(pos)
			{
				strncpy(mac,pos-2,17);
			}
			fclose(fp);
			return 1;
		}
	}
	fclose(fp);
	return 0;
}


int host_to_ip(char *hostname,char *ip_config)
{
	char **pptr = NULL;
	struct hostent *hptr = NULL;
	char str[20] = "";

	if((hptr = gethostbyname(hostname)) == NULL)
	{
		perror("gethostbyname:");
		return 1;
	}

	switch(hptr->h_addrtype)
	{
		case AF_INET:
			pptr = hptr->h_addr_list;
		//	for(; *pptr != NULL; pptr++)
			sprintf(ip_config,"%s",inet_ntop(hptr->h_addrtype, (void *)*pptr, str, sizeof(str)));
			break;
		default:
			break;
	}
	return 1;
}

void check_curl(char *cmd,char *response,int len)
{
	char buf[100] = "";   	
	FILE *ptr;   	
	if((ptr = popen(cmd, "r")) != NULL)
	{   		
		fgets(buf, len - 1, ptr);   			
		pclose(ptr);   		
		ptr = NULL;   		
		strncpy(response,buf,len - 1);	
	}	
	return;
}

void  send_udp_data(int port ,char *buf)
{
    int sock;
    struct sockaddr_in address;
    /* Initialize socket address structure for Interner Protocols */
    bzero(&address, sizeof(address)); // empty data structure
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr("127.0.0.1");
    address.sin_port = htons(port);
    /* Create a UDP socket */
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    sendto(sock, buf, strlen(buf), 0, (struct sockaddr *)&address, sizeof(address)); //address is the target of the message send
    close(sock);
    return;
}

void send_real_login(char *ip_src,char *mac_with_colon,char *phonenum)
{
	char login_buf[100] = "";
	send_udp_data(55000,ip_src);
	sprintf(login_buf,"ip=%s|mac=%s|mobile=%s",ip_src,mac_with_colon,phonenum);
	send_udp_data(50001,login_buf);
	return;
}

void send_url(char *ip,short port,char *url,char *response,char *data)
{
    struct sockaddr_in servaddr;
    int sockfd;
    bzero(&servaddr,sizeof(servaddr));
	
    servaddr.sin_family=AF_INET;
    servaddr.sin_port=htons(port);
    servaddr.sin_addr.s_addr=inet_addr(ip);
    sockfd=socket(AF_INET,SOCK_STREAM,0);
	struct timeval timeout={3,0};
    socklen_t timeout_len = sizeof(timeout);
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, timeout_len);
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, timeout_len);
	if(connect(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr))<0)
        return NULL;
	char data_buf[100] = "";
	char send_buf[1000] = "";
	sprintf(data_buf,"params=%s",data);
	sprintf(send_buf, "POST %s HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\nHost: %s:%d\r\nConnection: close\r\nCache-Control: no-cache \r\n\r\n\%s\r\n\r\n",url,strlen(data_buf),ip,port,data_buf);
	write(sockfd,send_buf,strlen(send_buf));
	char buffer[1000] = "";
	read(sockfd,buffer,sizeof(buffer));
	char *p = strstr(buffer,"status");
	if(p != NULL)
		strcpy(response,p);
	close(sockfd);
	return;
}
