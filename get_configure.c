#define _GNU_SOURCE
#include <stdio.h>
#include <pthread.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include "passenger_info.h"

#define file_path  "./config.txt"
int get_text_data(char* src,char* start,char* end,char* target,int limit)
{
	char *pos1=NULL,*pos2=NULL;

	pos1=(char *)strcasestr(src,start);
	if(pos1)
	{
		pos1+=strlen(start);
		pos2 = (char *)strcasestr(pos1, end);
		if(pos2==NULL)
			pos2 = strlen(src)+src;
		if(pos2&&(pos2-pos1<limit))
			memcpy(target, pos1, pos2-pos1);
	}
	return 1;
}


int getnvram(char *key, char *value)
{   
	char line[200] = {'\0'};
	char identify[200] = {'\0'};
	char line_key[100] = {'\0'};
	FILE *fp = fopen(file_path,"r");
	if(fp == NULL)
	{
		perror("open file failed!\n");
		return;
	}
	while(fgets(line,sizeof(line),fp))
	{
		memset(line_key,0,sizeof(line_key));
		get_text_data(line,"\"","\":",line_key,sizeof(line_key));
		if(strcmp(line_key,key) == 0)
		{
			get_text_data(line,"\":\"","\"",identify,sizeof(identify));
			strcpy(value,identify);
			fclose(fp);
			return 0;
		}
	}
	fclose(fp);
	return 1;
}
