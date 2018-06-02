#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
//#include <rpc/des_crypt.h>
#include <stdlib.h>
#include "decrypt.h"


char *make_time_str(char *time_str)
{
	static int day=0;
	static int count=0;
	char *ret_val=NULL;
	struct tm tm;
	time_t time_now = time(0);
	localtime_r(&time_now, &tm);
	sprintf(time_str,"%d-%02d-%02d %02d:%02d:%02d", 1900+tm.tm_year, tm.tm_mon+1, tm.tm_mday,tm.tm_hour,tm.tm_min, tm.tm_sec);
	return time_str;
}

int urldecode(char *str, int len)
{
    char *dest = str;
    char *data = str;

    int value;
    int c;

    while (len--) {
        if (*data == '+') {
        *dest = ' ';
        }
        else if (*data == '%' && len >= 2 && isxdigit((int) *(data + 1))
                 && isxdigit((int) *(data + 2)))
        {

            c = ((unsigned char *)(data+1))[0];
            if (isupper(c))
                c = tolower(c);
            value = (c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10) * 16;
            c = ((unsigned char *)(data+1))[1];
            if (isupper(c))
                c = tolower(c);
            value += c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10;

            *dest = (char)value ;
            data += 2;
            len -= 2;
        } else {
            *dest = *data;
        }
        data++;
        dest++;
    }
    *dest = '\0';
    return dest - str;
}

int base64(char *s,char *d)
{
    char CharSet[64]={

        'A','B','C','D','E','F','G','H',
        'I','J','K','L','M','N','O','P',
        'Q','R','S','T','U','V','W','X',
        'Y','Z','a','b','c','d','e','f',
        'g','h','i','j','k','l','m','n',
        'o','p','q','r','s','t','u','v',
        'w','x','y','z','0','1','2','3',
        '4','5','6','7','8','9','+','/'
        
        };

    unsigned char In[3];
    unsigned char Out[4];
    int cnt=0;

    if(!s||!d) return 0;

    for(;*s!=0;)
    {
        if(cnt+4>76)
        {
            *d++='\n';
            cnt=0;
        }

        if(strlen(s)>=3)
        {
            In[0]=*s;
            In[1]=*(s+1);
            In[2]=*(s+2);
            Out[0]=In[0]>>2;
            Out[1]=(In[0]&0x03)<<4|(In[1]&0xf0)>>4;
            Out[2]=(In[1]&0x0f)<<2|(In[2]&0xc0)>>6;
            Out[3]=In[2]&0x3f;
            *d=CharSet[Out[0]];
            *(d+1)=CharSet[Out[1]];
            *(d+2)=CharSet[Out[2]];
            *(d+3)=CharSet[Out[3]];
            
            s+=3;
            d+=4;
        }
        else if(strlen(s)==1)
        {
            In[0]=*s;
            Out[0]=In[0]>>2;
            Out[1]=(In[0]&0x03)<<4|0;
            *d=CharSet[Out[0]];
            *(d+1)=CharSet[Out[1]];
            *(d+2)='=';
            *(d+3)='=';
            s+=1;
            d+=4;
        }
        else if(strlen(s)==2)
        {
            In[0]=*s;
            In[1]=*(s+1);
            Out[0]=In[0]>>2;
            Out[1]=(In[0]&0x03)<<4|(In[1]&0xf0)>>4;
            Out[2]=(In[1]&0x0f)<<2|0;
            *d=CharSet[Out[0]];
            *(d+1)=CharSet[Out[1]];
            *(d+2)=CharSet[Out[2]];
            *(d+3)='=';
            s+=2;
            d+=4;
        }
        cnt+=4;
    }
    *d='\0';
    return 1;
}



void replaceFirst(char *str1,char *str2,char *str3)
{
    int len = strlen(str1)+1;
//    char str4[strlen(str1)+1];
    char* str4 = (char*)malloc(len);
    if(!str4)
        return;
    char *p;
    strcpy(str4,str1);
    if((p=strstr(str1,str2))!=NULL)/*p指向str2在str1中第一次出现的位置*/
    {
        while(str1!=p&&str1!=NULL)/*将str1指针移动到p的位置*/
        {
            str1++;
        }
        str1[0]='\0';/*将str1指针指向的值变成/0,以此来截断str1,舍弃str2及以后的内容，只保留str2以前的内容*/
        strcat(str1,str3);/*在str1后拼接上str3,组成新str1*/
        strcat(str1,strstr(str4,str2)+strlen(str2));/*strstr(str4,str2)是指向str2及以后的内容(包括str2),strstr(str4,str2)+strlen(str2)就是将指针向前移动strlen(str2)位，跳过str2*/
    }
    free(str4);
}
/*将str1出现的所有的str2都替换为str3*/
void replace(char *str1,char *str2,char *str3)
{
    while(strstr(str1,str2)!=NULL)
    {
        replaceFirst(str1,str2,str3);
    }
}

void deleteFirst(char *str1,char *str2,char *str3)
{
    int len = strlen(str1)+1;
//    char str4[strlen(str1)+1];
    char* str4 = (char*)malloc(len);
    if(!str4)
        return;
    char *start,*end;
    //strcpy(str4,str1);
    if((start=strcasestr(str1,str2))!=NULL)/*p指向str2在str1中第一次出现的位置*/
    {
        if((end = strcasestr(start,str3)) != NULL)
        {
            *start = '\0';
            end = end + strlen(str3);
            strcpy(str4,end);
            strcat(start,str4);
        }
    }
    free(str4);
}
void delete(char *str1,char *str2,char *str3)
{
    while(strcasestr(str1,str2)!=NULL)
    {
        deleteFirst(str1,str2,str3);
    }
}

void CleanWord(char* src)
{
    replace(src,"&lt;","<");
    replace(src,"&gt;",">");
    replace(src,"&nbsp;"," ");

    int nLen = strlen(src);
    int i = 0;
    for( i =0;i<nLen;i++){
        if(src[i] == '\r' || src[i] == '\n')
            src[i] = ' ';
        }
    char *drop = NULL;
}

void FormatUrlWord(char* src, int isrcLen, char* dst, int idstLen)
{
    int i = 0, count = 0;
    char temp[10] ="";
    
    for(; i<isrcLen && count<idstLen; i++)
    {
        memset(temp,0,sizeof(temp));
        if(src[i] >=0x21 && src[i]<=0x7e)
            sprintf(temp,"%c",src[i]);
        else
            sprintf(temp,"%%%x",(unsigned char)src[i]);
        strcat(dst,temp);
        count += strlen(temp);
    }
}

void WriteFile(char* data,int nLen)
{
    char* DeData = (char*)malloc(nLen * 2);
    if(DeData)
    {
        memset(DeData,0,nLen * 2);
        base64(data,DeData);
        strcat(DeData,"\r\n");

        FILE *f;
        if(f=fopen("/tmp/nand/project/boyi_app/contentlog.txt","a+"))
        {
            fwrite(DeData,strlen(DeData),1,f);
            fclose(f);
        }
    }
    
}
void FileLog(int nType,char* ID,char* param1,char* param2)
{
    int nLogLen = strlen(ID)+strlen(param1)+strlen(param2)+100;
    char* LogData = (char*)malloc(nLogLen);
    if(LogData)
    {
        memset(LogData,0,nLogLen);
        char* Type = NULL;
        switch(nType)
        {
        case ID_TYPE:
            Type = "普通身份";
            break;
        case BBS_TYPE:
            Type = "论坛内容";
            break;
        case MAIL_TYPE:
            Type = "邮件内容";
            break;
        case CHAT_TYPE:
            Type = "聊天内容";
            break;
        case URL_TYPE:
            Type = "URL";
            break;
        }
        
        char NowTime[20] = {0};
        make_time_str(NowTime);
        if(nType == ID_TYPE)
            sprintf(LogData,"time:%s type:%s id:%s username:%s",NowTime,Type,ID,param1);
        else if(nType == BBS_TYPE || nType == MAIL_TYPE)
            sprintf(LogData,"time:%s type:%s id:%s title:%s content:%s",NowTime,Type,ID,param1,param2);
        else if(nType == CHAT_TYPE)
            sprintf(LogData,"time:%s type:%s id:%s content:%s",NowTime,Type,ID,param1);
        else if(nType == URL_TYPE)
            sprintf(LogData,"time:%s type:%s id:%s URL:%s",NowTime,Type,ID,param1);

        WriteFile(LogData,strlen(LogData));
        free(LogData);
    }
}





