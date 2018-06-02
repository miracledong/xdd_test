#define _GNU_SOURCE
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <syslog.h>
#include <stdio.h>
#include <stdio.h>
#include <pthread.h>
#include <semaphore.h>
//#include <linux/netfilter.h>
#include <syslog.h>
//#include <libnetfilter_queue/libnetfilter_queue.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

 
#include "list.h"
//#include "filter.h"

#include "session.h"
#include "handle_mem.h"

//#define SES_DEBUG 1

#define HASH_SESSION_COUNT (1<<10)

static struct list_head  session_hash_list[HASH_SESSION_COUNT];//no lock by now

static int session_count = 0;

unsigned int calc_session_hash(unsigned int srcip, unsigned short srcport,unsigned int dstip,unsigned short dstport)
{
    int hash_key=0;

    hash_key += srcip;
    hash_key += srcport;
    hash_key += dstip;
    hash_key += dstport;

    hash_key &=(HASH_SESSION_COUNT-1);

    return hash_key;
}

void free_session_sub_param(struct session_t *s)
{
    if (s == NULL)
        return;

    memfree(s->rep_data_buf);
    memfree(s->rep_head_buf);

    memfree(s->req_data_buf);
    memfree(s->req_head_buf);
    memfree(s->cookie_buf);
    memfree(s->user_agent);

    memfree(s->decode_buf);

    memfree(s->key_word);
    memfree(s->referer);
    struct url_s *url_tmp = s->url_data;
    if(url_tmp){
        memfree (s->url_data);
    }
}


struct session_t * add_session_to_list(struct list_head *list, unsigned int srcip, unsigned short srcport,unsigned int dstip,unsigned short dstport)
{

    struct session_t *session_tmp = NULL;

    session_tmp = (struct session_t *)malloc(sizeof(struct session_t));//no free for now; will freed when prog restart
    if(session_tmp == NULL){
        printf("*ERROR  func:%s line:%d*\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    memset(session_tmp, 0, sizeof(struct session_t));

    session_tmp->decode_buf = NULL;
    session_tmp->decode_len = 0;

//    printf("*ERROR    func:%s line:%d*\n", __FUNCTION__, __LINE__);

    
    session_tmp->rep_data_buf = NULL;
    session_tmp->rep_buf_len = 0;
    /*    */

    session_tmp->rep_data_buf = malloc(MAX_PARSE_BUF_SIZE);
    if(session_tmp->rep_data_buf == NULL){
        free_session_sub_param(session_tmp);
        memfree(session_tmp);
        printf("*ERROR  func:%s line:%d*\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    session_tmp->rep_buf_len = MAX_PARSE_BUF_SIZE;
    memset(session_tmp->rep_data_buf, 0, MAX_PARSE_BUF_SIZE);


//    printf("*ERROR    func:%s line:%d*\n", __FUNCTION__, __LINE__);
    session_tmp->rep_head_buf = malloc(PROTO_MAX_PARSE_BUF_SIZE);
    if(session_tmp->rep_head_buf == NULL){
        free_session_sub_param(session_tmp);
        memfree(session_tmp);
        printf("*ERROR  func:%s line:%d*\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    session_tmp->rep_head_len = PROTO_MAX_PARSE_BUF_SIZE;
    memset(session_tmp->rep_head_buf, 0, PROTO_MAX_PARSE_BUF_SIZE);

    session_tmp->req_data_buf = malloc(PROTO_MAX_PARSE_BUF_SIZE);
    if(session_tmp->req_data_buf == NULL){
        free_session_sub_param(session_tmp);
        memfree(session_tmp);
        printf("*ERROR  func:%s line:%d*\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    session_tmp->req_buf_len = PROTO_MAX_PARSE_BUF_SIZE;
    memset(session_tmp->req_data_buf, 0, PROTO_MAX_PARSE_BUF_SIZE);
    

    session_tmp->req_head_buf = malloc(PROTO_MAX_PARSE_BUF_SIZE);
    if(session_tmp->req_head_buf == NULL){
        free_session_sub_param(session_tmp);
        memfree(session_tmp);
        printf("*ERROR  func:%s line:%d*\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    session_tmp->req_head_len = PROTO_MAX_PARSE_BUF_SIZE;
    memset(session_tmp->req_head_buf, 0, PROTO_MAX_PARSE_BUF_SIZE);


    session_tmp->referer= malloc(MAX_REFER_SIZE);
    if(session_tmp->referer == NULL){
        free_session_sub_param(session_tmp);
        memfree(session_tmp);
        printf("*ERROR  func:%s line:%d*\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    session_tmp->refer_len = MAX_REFER_SIZE;
    memset(session_tmp->referer, 0, MAX_REFER_SIZE);

    session_tmp->cookie_buf= malloc(MAX_COOKE_BUF_SIZE);
    if(session_tmp->cookie_buf == NULL){
        free_session_sub_param(session_tmp);
        memfree(session_tmp);
        printf("*ERROR  func:%s line:%d*\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    session_tmp->cookie_len= MAX_COOKE_BUF_SIZE;
    memset(session_tmp->cookie_buf, 0, MAX_COOKE_BUF_SIZE);

    session_tmp->user_agent= malloc(MAX_USER_AGENT_SIZE);
    if(session_tmp->user_agent == NULL){
        free_session_sub_param(session_tmp);
        memfree(session_tmp);
        printf("*ERROR  func:%s line:%d*\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    memset(session_tmp->user_agent, 0, MAX_USER_AGENT_SIZE);


    session_tmp->url_data = NULL;
    
    session_tmp->srcip=srcip;
    session_tmp->dstip=dstip;
    session_tmp->srcport=srcport;
    session_tmp->dstport=dstport;

    session_tmp->rep_content_len = -1;
    session_tmp->req_content_len = -1;
    session_tmp->timestamp = time(0);
    session_tmp->ses_st = SES_INIT;
    session_tmp->keep_alive = true;
    session_tmp->chunked = false;
    session_tmp->doUnCompressed = false;
    session_tmp->rep_data_offset = 0;
    session_tmp->rep_head_offset = 0;
    session_tmp->req_data_offset = 0;
    session_tmp->req_head_offset = 0;
    session_tmp->content_type = CON_TYPE_NONE;
    session_tmp->compress_type = HTTP_COMPRESS_NONE;
    session_tmp->cookie_len = 0;
    

    INIT_LIST_HEAD(&(session_tmp->head));
    list_add_head( &(session_tmp->head), list);
    session_count++;

    return session_tmp;

}

struct session_t * set_session_status(struct session_t * session)
{

    unsigned int srcip;
    unsigned int dstip;
    unsigned short srcport;
    unsigned short dstport;

    int i = 0;

    unsigned int hash_key;

    unsigned char *output_point = NULL;
    unsigned char output_data[MAX_PARSE_BUF_SIZE+1]="";

    struct iphdr *iphptr;
    struct tcphdr *tcphptr;
    

    struct url_s *url_tmp = NULL;
    url_tmp = (struct url_s *)(session->url_data);


    if(session->key_word && session->url_data){
        //url_tmp->status = session->status;

    
        if(url_tmp->hostip == session->srcip)
            srcip = session->dstip;
        else
            dstip = session->srcip;
        

        }
    
    time_t time_now = time(0);
    if(url_tmp&&(time_now - url_tmp->last_visit_time)>3600){
        url_tmp->last_visit_time = time_now;
        url_tmp->visit_count = 0;
    }

    fflush(stdout);
    del_session_from_list(session);

}

struct session_t * del_session_from_list(struct session_t *session)
{
    struct session_t *session_tmp = session;

    if (!(list_empty(&session_tmp->head)))
        list_del(&(session_tmp->head));

    free_session_sub_param(session_tmp);
            
    if (session_tmp)
        free(session_tmp);
    session_tmp = NULL;
            
    session_count--;

    return NULL;
}


struct session_t *find_session_in_list(struct list_head *list, unsigned int srcip, unsigned short srcport,unsigned int dstip,unsigned short dstport)
{

    struct session_t *session_tmp, *n;
    unsigned int now = time(0);

    static int count=0; 

    int limit_count = 0;
    list_for_each_entry_safe(session_tmp, n, list, head)
    {
        if(((session_tmp->srcip==srcip&&session_tmp->dstip==dstip)
            ||(session_tmp->srcip==dstip&&session_tmp->dstip==srcip)) &&
            ((session_tmp->srcport==srcport&&session_tmp->dstport==dstport)
            ||(session_tmp->srcport==dstport&&session_tmp->dstport==srcport)))
        {
            /*char MyIp[16] = {0};
            char HostIp[16] = {0};
            sprintf(MyIp,"%s",inet_ntoa(*(struct in_addr*)&srcip));
            sprintf(HostIp,"%s",inet_ntoa(*(struct in_addr*)&dstip));
            int Sport = ntohs(srcport);
            int Dport = ntohs(dstport);
            printf("SAME %s:%d %s:%d %d\n",MyIp,Sport,HostIp,Dport,session_count);*/
            
            session_tmp->timestamp = now;
            return session_tmp;
        }else{

            /*char MyIp[16] = {0};
            char HostIp[16] = {0};
            sprintf(MyIp,"%s",inet_ntoa(*(struct in_addr*)&srcip));
            sprintf(HostIp,"%s",inet_ntoa(*(struct in_addr*)&dstip));
            int Sport = ntohs(srcport);
            int Dport = ntohs(dstport);
            printf("NOT %s:%d %s:%d %d\n",MyIp,Sport,HostIp,Dport,session_count);*/
            
            if((session_tmp->timestamp+SESSION_TIMEOUT < now) || limit_count >= 10)
            {

                if (!(list_empty(&(session_tmp->head)))){
                    list_del(&(session_tmp->head));
                }
                count++;
                //if(session_tmp->timestamp+30 < now)
            //    if(count%100==0)
            //        printf("session_tmp->timestamp+30 < now :%d \t count:%d \n", session_tmp->timestamp -  now, count);

                free_session_sub_param(session_tmp);

                if (session_tmp)
                    free(session_tmp);
                session_tmp = NULL;

                session_count--;
            }
        }
        limit_count++;
    }

    return NULL;
}


#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define NS_ERROR_INVALID_CONTENT_ENCODING 27

#define GZIP_HEAD_TAGS_LEN 10
#define GZIP_END_TAGS_LEN 8
#define GZIP_TAGS_LEN (GZIP_HEAD_TAGS_LEN + GZIP_END_TAGS_LEN)

#define ASCII_FLAG   0x01 /* bit 0 set: file probably ascii text */
#define HEAD_CRC     0x02 /* bit 1 set: header CRC present */
#define EXTRA_FIELD  0x04 /* bit 2 set: extra field present */
#define ORIG_NAME    0x08 /* bit 3 set: original file name present */
#define COMMENT      0x10 /* bit 4 set: file comment present */
#define RESERVED     0xE0 /* bits 5..7: reserved */

static unsigned gz_magic[2] = {0x1f, 0x8b}; /* gzip magic header */

int resetHttpSessionContent(struct session_t * ses)
{

    if (ses == NULL)
        return 1;    

    ses->rep_data_offset = 0;
    if(ses->rep_data_buf)
        memset(ses->rep_data_buf, 0, ses->rep_buf_len);    

    ses->rep_head_offset = 0;
    if(ses->rep_head_buf)
        memset(ses->rep_head_buf, 0, ses->rep_head_len);    

    ses->req_data_offset = 0;
    if(ses->req_data_buf)
        memset(ses->req_data_buf, 0, ses->req_buf_len);    

    ses->req_head_offset = 0;
    if(ses->req_head_buf)
        memset(ses->req_head_buf, 0, ses->req_head_len); 

    ses->refer_len = 0;
    if(ses->referer)
        memset(ses->referer, 0, MAX_REFER_SIZE); 

    ses->cookie_len = 0;
    if(ses->cookie_buf)
        memset(ses->cookie_buf, 0, MAX_COOKE_BUF_SIZE);    

    if(ses->user_agent)
        memset(ses->user_agent, 0, MAX_USER_AGENT_SIZE);    

    ses->req_head_completed = 0;

    memfree(ses->decode_buf);
    ses->decode_len = 0;
    
    return 0;
}

int anlysisHttpResponse(struct session_t * session_tmp, char * match, int data_len)
{
    int contentLen = 0;
    char *charset;
    charset = NULL;
    char strLen[33] = {0};
    int i = 0;

    session_tmp->ses_st = SES_REP;

    if (data_len < 40)
        return 1;

    //printf("Begin anlysisHttpResponse\n");

    if (charset = strstr(match, "Transfer-Encoding: chunked"))
    {
        //printf("chunked\n");
        session_tmp->chunked = true;
    }
    
    if(!session_tmp->chunked && (charset=strstr(match, "Content-Length:")))
    {
        
        i=0;
        charset = charset + 16;
        while(*(charset+i)!='\r'&&*(charset+i)!='\n'&&*(charset+i)!='\0'&&*(charset+i)!=' '&&i<32)
            i++;
        strncpy(strLen, charset, i);
        strLen[i] = '\0';
        contentLen = atoi(strLen);
        
        session_tmp->keep_alive = true;
        struct url_s *url = (struct url_s *)session_tmp->url_data;
        //printf("REP Content-Length: --------------%s %s\n",strLen,url->url);
    } 

    if (contentLen > 0 && contentLen < MAX_PARSE_BUF_SIZE)
    {
        session_tmp->rep_content_len = contentLen;
    }
    else if(0)
    {
        memfree(session_tmp->rep_data_buf);
        session_tmp->rep_data_buf = malloc(MAX_PARSE_BUF_SIZE);
        if(session_tmp->rep_data_buf == NULL)
        {
            free_session_sub_param(session_tmp);
            memfree(session_tmp);
            printf("*ERROR  func:%s line:%d*\n", __FUNCTION__, __LINE__);
            //return NULL;
            return 0;
        }
        session_tmp->rep_buf_len = MAX_PARSE_BUF_SIZE;
        memset(session_tmp->rep_data_buf, 0, MAX_PARSE_BUF_SIZE);
    }

    if (charset=strstr(match, "Connection: close"))
        session_tmp->keep_alive = false;

    if (charset=strstr(match, "Content-Encoding:"))
    {
        char ctype[20] = {0};
        charset = charset + 18;

        strncpy(ctype, charset, 19);
        ctype[19] = '\0';
        //printf("ctype----------------------------------------- %s\n", ctype);
        if ((strncmp(charset, "gzip", 4) == 0) || (strncmp(charset, "x-gzip", 6) == 0))
            session_tmp->compress_type = HTTP_COMPRESS_GZIP;
        else if (strncmp(charset, "deflate", 4) == 0)
            session_tmp->compress_type = HTTP_COMPRESS_DEFLATE;
        else if ((strncmp(charset, "compress", 4) == 0) || (strncmp(charset, "x-compress", 6) == 0))
            session_tmp->compress_type = HTTP_COMPRESS_COMPRESS;
    }
    else 
        session_tmp->compress_type = HTTP_COMPRESS_NONE;

    if (charset = strstr(match, "charset="))
    {
        int i=0;
        charset += 8;    
        while(*(charset+i)!='\r'&&*(charset+i)!='\n'&&*(charset+i)!='\0'&&*(charset+i)!=' '&&i<31)
            i++;
        strncpy(session_tmp->charset, charset, i);
        session_tmp->charset[i] = '\0';
    }

    if (charset=strstr(match, "Content-Type: "))
    {
        charset += 14;
        if ((strncmp(charset, "image", 5) == 0) || ((strncmp(charset, "audio", 5) == 0)) || (strncmp(charset, "video", 5) == 0))
            session_tmp->content_type = CON_TYPE_IMAGE_VIDEO_AUDIO;
    }

    if (charset = strstr(match, "\r\n\r\n"))
        charset = charset + 4;
    else 
    {    
        if ((data_len + session_tmp->rep_head_offset) < PROTO_MAX_PARSE_BUF_SIZE)
        {
            memcpy(session_tmp->rep_head_buf + session_tmp->rep_head_offset, match, data_len);
            session_tmp->rep_head_offset += data_len;
            session_tmp->rep_head_buf[session_tmp->rep_head_offset] = '\0';
        }


        //printf("Could not find press break\n");
        return 1;
    }

    //printf(" ---> data_len = %d, len = %d\n", data_len, charset - match);
    int rep_head_len=0;
    if(charset)
        rep_head_len = charset - match;


    if ((rep_head_len + session_tmp->rep_head_offset) < PROTO_MAX_PARSE_BUF_SIZE)
    {    
        memcpy(session_tmp->rep_head_buf + session_tmp->rep_head_offset, match, rep_head_len);
        session_tmp->rep_head_offset += rep_head_len;
        session_tmp->rep_head_buf[session_tmp->rep_head_offset] = '\0';
    }

    if ((data_len - rep_head_len) > 0 )
    {
        if ((data_len - rep_head_len + session_tmp->rep_data_offset ) < MAX_PARSE_BUF_SIZE)
        { 
            if((data_len - rep_head_len + session_tmp->rep_data_offset )>session_tmp->rep_buf_len)
            {
            //printf("-match:%s\n", match);
            //printf("---data_len:%d-rep_head_len:%d session_tmp->rep_data_offset:%d session_tmp->rep_buf_len:%d\n", data_len, rep_head_len,session_tmp->rep_data_offset, session_tmp->rep_buf_len);
            }
             memcpy(session_tmp->rep_data_buf + session_tmp->rep_data_offset, charset, data_len - rep_head_len);
            session_tmp->rep_data_offset += (data_len - rep_head_len);
        }
    }

    return 0;
}

int anlysisHttpRequest(struct session_t * session, char * match, int data_len, int sn)
{
    char *index = NULL;

    //printf("Begin anlysisHttpRequest\n");

    session->ses_st = SES_REQ;
    if(!strncmp(match, "POST ",5)){
        //printf("line:%d Begin anlysisHttpRequest\n", __LINE__);
        session->request_type= REQ_TYPE_POST;
    }
    else if(!strncmp(match, "GET ",4)){
        //printf("line:%d Begin anlysisHttpRequest\n", __LINE__);
        session->request_type= REQ_TYPE_GET;
        }
    
    if(session->url_data== NULL && url_filter(match, data_len, session, sn) ==0)
    {
        return 2;
    }
    
    struct url_s *url_tmp = (struct url_s*)session->url_data;
    if (index = strstr(match, "\r\n\r\n"))
    {
        session->req_head_completed = 1;
        index = index + 4;
    }
    else 
    {
        if ((data_len + session->req_head_offset) < PROTO_MAX_PARSE_BUF_SIZE)
        {
             memcpy(session->req_head_buf + session->req_head_offset, match, data_len);
            session->req_head_offset += data_len;
            session->req_head_buf[session->req_head_offset] = '\0';
        }

        //printf("Request could not find press break\n");
        return 0;
    }

    int head_len=0;
    if(index)
        head_len = index - match;

    if ((head_len + session->req_head_offset) < session->req_head_len)
    {
        memcpy(session->req_head_buf + session->req_head_offset, match, head_len);
        session->req_head_offset += head_len;
        session->req_head_buf[session->req_head_offset] = '\0';
    }

    if ((data_len - head_len) > 0 )
    {
        if ((data_len - head_len + session->req_data_offset ) < PROTO_MAX_PARSE_BUF_SIZE)
        { 
             memcpy(session->req_data_buf + session->req_data_offset, index, data_len - head_len);
            session->req_data_offset += (data_len - head_len);
        }
    }

    if(session->req_head_completed)
    {
        int contentLen = 0;
        char *charset = NULL;
        char strLen[33] = {0};
        if(charset=strstr(session->req_head_buf, "Content-Length:"))
        {
            int i=0;
            charset = charset + 16;
            while(*(charset+i)!='\r'&&*(charset+i)!='\n'&&*(charset+i)!='\0'&&*(charset+i)!=' '&&i<32)
                i++;
            strncpy(strLen, charset, i);
            strLen[i] = '\0';
            
            contentLen = atoi(strLen);
            struct url_s *url = (struct url_s *)session->url_data;
            //printf("REQ Content-Length: --------------%s %s\n",strLen,url->url);
        }

        if (contentLen > 0 && contentLen < MAX_PARSE_BUF_SIZE)
        {
            session->req_content_len = contentLen;
        }
        
        //add cookie buf 2014/4/9
        char* cookie_start = 0;
        if(cookie_start = strstr(session->req_head_buf, "Cookie:"))
        {
            cookie_start += 7;
            char* cookie_end = 0;
            if(cookie_end = strstr(cookie_start, "\r\n"))
            {
                int cookie_len = cookie_end - cookie_start;
                if(cookie_len < MAX_COOKE_BUF_SIZE)
                {
                    memcpy(session->cookie_buf,cookie_start,cookie_len);
                    session->cookie_len = cookie_len;
                    //printf("Cookie:%s",session->cookie_buf);
                }
            }
        }

        //add referer 2015/3/6
        char* refer_start = 0;
        if(refer_start = strstr(session->req_head_buf, "Referer:"))
        {
            refer_start += 7;
            char* refer_end = 0;
            if(refer_end = strstr(refer_start, "\r\n"))
            {
                int refer_len = refer_end - refer_start;
                if(refer_len < MAX_REFER_SIZE)
                {
                    memcpy(session->referer,refer_start,refer_len);
                    session->refer_len = refer_len;
                    //printf("Referer:%s",session->referer);
                }
            }
        }

        //add user agent 2014/6/17
        char* user_agent_start = 0;
        if(user_agent_start = strstr(session->req_head_buf, "User-Agent:"))
        {
            user_agent_start += 7;
            char* user_agent_end = 0;
            if(user_agent_end = strstr(user_agent_start, "\r\n"))
            {
                int agent_len = user_agent_end - user_agent_start;
                if(agent_len < MAX_USER_AGENT_SIZE)
                {
                    memcpy(session->user_agent,user_agent_start,agent_len);
                    //printf("User-Agent:%s",session->user_agent);
                }
            }
        }

        
    }

    return 0;
}
/*
 *  In response (HTTP/1.1 200 Ok)
 *      Keep-Alive Enable
 *          Contert-Length exist only    --- the length is know
 *          Transfer-Encodeing:chunked    --- every chunked length is know
 *          Contert-Length exist && Transfer-Encodeing:chunked  --- every chunked length is know
 *      Keep-Alive Disable
 *          tcp syn = 1, indicate that end of transmission
 */

struct session_t * dump_session(struct session_t * session)
{
    struct session_t *session_tmp = NULL;

    session_tmp = (struct session_t *)malloc(sizeof(struct session_t));//no free for now; will freed when prog restart
    if(session_tmp == NULL){
        printf("*ERROR  func:%s line:%d*\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    memset(session_tmp, 0, sizeof(struct session_t));

    session_tmp->decode_buf = NULL;
    session_tmp->decode_len = 0;

//    printf("*ERROR    func:%s line:%d*\n", __FUNCTION__, __LINE__);

    
    session_tmp->rep_data_buf = NULL;
    session_tmp->rep_buf_len = 0;
    /*    */
//    printf("----line:%d ---session->ses_st:%d ---->url:\n", __LINE__,session_tmp->ses_st);

    session_tmp->rep_data_buf = malloc(MAX_PARSE_BUF_SIZE);
    if(session_tmp->rep_data_buf == NULL){
        free_session_sub_param(session_tmp);
        memfree(session_tmp);
        printf("*ERROR  func:%s line:%d*\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    session_tmp->rep_buf_len = session->rep_buf_len;
    if(session->rep_data_buf)
        memcpy(session_tmp->rep_data_buf, session->rep_data_buf, session->rep_data_offset);

//printf("----line:%d ---session->ses_st:%d ---->url:\n", __LINE__,session_tmp->ses_st);

//    printf("*ERROR    func:%s line:%d*\n", __FUNCTION__, __LINE__);
    session_tmp->rep_head_buf = malloc(PROTO_MAX_PARSE_BUF_SIZE);
    if(session_tmp->rep_head_buf == NULL){
        free_session_sub_param(session_tmp);
        memfree(session_tmp);
        printf("*ERROR  func:%s line:%d*\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    session_tmp->rep_head_len = session->rep_head_len;
    if(session->rep_head_buf)
        memcpy(session_tmp->rep_head_buf, session->rep_head_buf, session->rep_head_offset);
//    printf("----line:%d ---session->ses_st:%d ---->url:\n", __LINE__,session_tmp->ses_st);

    session_tmp->req_data_buf = malloc(PROTO_MAX_PARSE_BUF_SIZE);
    if(session_tmp->req_data_buf == NULL){
        free_session_sub_param(session_tmp);
        memfree(session_tmp);
        printf("*ERROR  func:%s line:%d*\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    session_tmp->req_buf_len = session->req_buf_len;
    if(session->req_data_buf)
        memcpy(session_tmp->req_data_buf, session->req_data_buf, session->req_data_offset);
    //printf("----line:%d ---session->req_buf_len:%d ---->url:\n", __LINE__,session->req_data_offset);

    session_tmp->req_head_buf = malloc(PROTO_MAX_PARSE_BUF_SIZE);
    if(session_tmp->req_head_buf == NULL){
        free_session_sub_param(session_tmp);
        memfree(session_tmp);
        printf("*ERROR  func:%s line:%d*\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    session_tmp->req_head_len = session->req_head_len;
    if(session->req_head_buf)
        memcpy(session_tmp->req_head_buf, session->req_head_buf, session->req_head_offset);
//    printf("----line:%d ---session->ses_st:%d ---->url:\n", __LINE__,session_tmp->ses_st);

    session_tmp->cookie_buf= malloc(MAX_COOKE_BUF_SIZE);
    if(session_tmp->cookie_buf == NULL){
        free_session_sub_param(session_tmp);
        memfree(session_tmp);
        printf("*ERROR    func:%s line:%d*\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    session_tmp->cookie_len= session->cookie_len;
    if(session->cookie_buf)
        memcpy(session_tmp->cookie_buf, session->cookie_buf, session->cookie_len);

    session_tmp->referer= malloc(MAX_REFER_SIZE);
    if(session_tmp->referer == NULL){
        free_session_sub_param(session_tmp);
        memfree(session_tmp);
        printf("*ERROR    func:%s line:%d*\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    session_tmp->refer_len= session->refer_len;
    if(session->referer)
        memcpy(session_tmp->referer, session->referer, session->refer_len);


    session_tmp->url_data = session->url_data;
    session->url_data=NULL;

    
    session_tmp->srcip=0;
    session_tmp->dstip=0;
    session_tmp->srcport=0;
    session_tmp->dstport=0;

    session_tmp->request_type = session->request_type;

    session_tmp->rep_content_len = session->rep_content_len;
    session_tmp->req_content_len = session->req_content_len;
    session_tmp->req_head_completed = 0;
    
    session_tmp->timestamp = session->timestamp;
    session_tmp->ses_st = SES_FIN;
    session_tmp->keep_alive = session->keep_alive;
    session_tmp->chunked = session->chunked;
    session_tmp->doUnCompressed = false;
    session_tmp->rep_data_offset = session->rep_data_offset;
    session_tmp->rep_head_offset = session->rep_head_offset;
    session_tmp->req_head_offset= session->req_head_offset;
    session_tmp->req_data_offset = session->req_data_offset;
    
    session_tmp->content_type = session->content_type;
    session_tmp->compress_type = session->compress_type;

    
    INIT_LIST_HEAD(&(session_tmp->head));
    session_count++;
    return session_tmp;

}



struct session_t * do_session_filter(char *data, int sn)
{
    if(data == NULL || strlen(data) == 0)
    {
        printf("Empty data session!!\n");
        return NULL;
    }
    unsigned int srcip=0;
    unsigned int dstip=0;
    unsigned short srcport=0;
    unsigned short dstport=0;

    struct session_t * session_tmp=NULL;
    struct list_head *head=NULL;

    unsigned int hash_key=0;

    struct iphdr *iphptr=NULL;
    struct tcphdr *tcphptr=NULL;
    char *match;
    int payload_offset, data_len=0;

    iphptr = (struct iphdr *)data;
    tcphptr = (struct tcphdr *)(data + (iphptr->ihl<<2));
    payload_offset = ((iphptr->ihl)<<2) + (tcphptr->doff<<2);
    match = (char *)(data + payload_offset);
    data_len = htons(iphptr->tot_len)-(((iphptr->ihl)<<2) + (tcphptr->doff<<2));

    
    if (data_len <= 0)
        return NULL;

    srcip = iphptr->saddr;
    dstip = iphptr->daddr;
    srcport = tcphptr->source;
    dstport = tcphptr->dest;
    head = &session_hash_list[hash_key];
    session_tmp = find_session_in_list(head, srcip, srcport, dstip, dstport);

   // if(session_count > 30000){
    if(session_count > 3000){
        printf("too many sessions session_count:%d\n", session_count);
        return NULL;
    }
    if(data_len<0)
        printf("func:%s line:%d  session_count:%d data_len:%d\n", __FUNCTION__, __LINE__, session_count, data_len);

    if(session_tmp == NULL)
    {
        session_tmp = add_session_to_list(head, srcip, srcport, dstip, dstport);
        if(session_tmp == NULL)
        {
            return NULL;
        }
    }

    if (match == NULL)
        return session_tmp;

        if((data_len > 12) 
        && (!strncmp(match, "HTTP/1.1 ", 9) 
        || !strncmp(match, "HTTP/1.0 ", 9)
        ))// request end

    {
        /*if(session_tmp->ses_st == SES_BILIN)
            anlysisHttpResponse(session_tmp, match, data_len);
        else*/
        session_tmp->ses_st == SES_FIN;
        goto EXIT;
    }
    else if ((data_len > 5) && (!strncmp(match, "GET ", 4) || !strncmp(match, "POST ",5) || !strncmp(match, "HEAD ",5)))
    {
        struct session_t * session_tmp1=NULL;
        struct session_t * session_tmp2=session_tmp;
        if(session_tmp->ses_st != SES_INIT)
        {
            struct url_s *url = (struct url_s *)session_tmp->url_data;
            if(session_count > 5000)
            {// for mem lack
                printf("too many sessions session_count:%d\n", session_count);
                exit(-1);
            }
            session_tmp1 = dump_session(session_tmp);

            if(session_tmp1 == NULL) 
            {
                return NULL;
            }
            session_tmp2 = session_tmp;
            session_tmp = session_tmp1;
        }
        resetHttpSessionContent(session_tmp2);
        anlysisHttpRequest(session_tmp2, match, data_len, sn);
        goto EXIT;
    }
    else if(session_tmp->ses_st == SES_INIT)
    {
        session_tmp->ses_st == SES_FIN;
    }
    
    if (session_tmp->ses_st == SES_FIN)
    {
        return session_tmp;
    }

    if (session_tmp->ses_st == SES_REQ)
    {
        session_tmp->timestamp = time(0);//set time stamp

        if(session_tmp->req_data_offset+data_len >= session_tmp->req_buf_len)
        {
            session_tmp->ses_st = SES_OVER_BUF;
            goto EXIT;
        }
        
        if(session_tmp->pkt_count++ >= MAX_PARSE_PKT_COUNT)//
        {
            session_tmp->ses_st = SES_OVER_PKT;
            goto EXIT;
        }

        if (session_tmp->url_data != NULL)
        {
            if(session_tmp->req_head_completed){
                 memcpy(session_tmp->req_data_buf + session_tmp->req_data_offset, match, data_len);
                session_tmp->req_data_offset += data_len;
                struct url_s *url = (struct url_s *)session_tmp->url_data;
                //printf("SES_REQ %d %d+++++ %s\n",session_tmp->req_data_offset,session_tmp->req_content_len,url->url);
            }
            else//head is not completed
                {
                anlysisHttpRequest(session_tmp, match, data_len, sn);
                }
        }
    }

    if (session_tmp->ses_st == SES_REP)
    {
        session_tmp->timestamp = time(0);//set time stamp

        if(data_len < 4)
        {
            goto EXIT;
        }
    
        if (session_tmp->content_type == CON_TYPE_IMAGE_VIDEO_AUDIO)
            goto EXIT;

        if(session_tmp->rep_data_offset+data_len >= session_tmp->rep_buf_len 
            || session_tmp->rep_data_offset+data_len >=MAX_PARSE_BUF_SIZE)
        {
            session_tmp->ses_st = SES_OVER_BUF;
            goto EXIT;
        }
        
        if(session_tmp->pkt_count++ >= MAX_PARSE_PKT_COUNT)
        {
            session_tmp->ses_st = SES_OVER_PKT;
            goto EXIT;
        }

        if (session_tmp->url_data != NULL)
        {
            memcpy(session_tmp->rep_data_buf + session_tmp->rep_data_offset, match, data_len);
            session_tmp->rep_data_offset += data_len;
            struct url_s *url = (struct url_s *)session_tmp->url_data;
            //printf("SES_REP %d %d+++++ %s\n",session_tmp->rep_data_offset,session_tmp->rep_content_len,url->url);
        }
    }

    //printf("-----------------------line%d, sn:%d\n", __LINE__, sn);
EXIT:
    if (session_tmp->chunked)
    {
        char *t;
    
        if (session_tmp->rep_data_offset>= 7) 
        {
    
            t = session_tmp->rep_data_buf+ (session_tmp->rep_data_offset - 7);
            if(memcmp(t, "\r\n0\r\n\r\n", 7) == 0) // \r\n0\r\n\r\n is the tag  of chuncked-end;
            {
                session_tmp->ses_st = SES_FIN;
            }
        }
        else if (session_tmp->rep_data_offset>= 4) // chunk len == 0
        {
    
            t = session_tmp->rep_data_buf+ (session_tmp->rep_data_offset - 4);
            if(memcmp(t, "\r\n\r\n", 4) == 0) // \r\n0\r\n\r\n is the tag  of chuncked-end;
            {
                session_tmp->ses_st = SES_FIN;
            }
        }
    }
    else 
    {
        if (session_tmp->rep_content_len > 0)
        {
            if (session_tmp->rep_data_offset >= session_tmp->rep_content_len)
                session_tmp->ses_st = SES_FIN;
        }

        if(session_tmp->ses_st == SES_REQ)
        {
            if(session_tmp->req_content_len == -1)
            {
                if(session_tmp->request_type == REQ_TYPE_GET && session_tmp->req_head_completed)
                    session_tmp->ses_st = SES_FIN;
            }
            else
            {
                struct url_s *url_tmp = (struct url_s *)session_tmp->url_data;
                //if bilin login,not parse,keep add
                if(session_tmp->req_data_offset >= session_tmp->req_content_len)
                {
                    session_tmp->ses_st = SES_FIN;                     
                    /*if(url_tmp && url_tmp->url && strstr(url_tmp->url,"/hujiao/j_spring_security_check"))
                        session_tmp->ses_st = SES_BILIN;*/
                }        
            }
        }
        if (tcphptr->fin == 1)
        {
            session_tmp->ses_st = SES_FIN;
        }
    }    
    //printf("-----------------------line%d, sn:%d\n", __LINE__, sn);

    return session_tmp;
}

int init_session_filter_list()
{
    int i = 0;
    for(i=0; i<HASH_SESSION_COUNT; i++)
        INIT_LIST_HEAD(&session_hash_list[i]);
}

void session_dump(struct session_t* session){

    if(!session){
        return;
    }

    char req_type[10] = {'\0'};
    if(session->request_type == REQ_TYPE_GET){
        strcpy(req_type, "GET");
    }else if(session->request_type == REQ_TYPE_POST){
        strcpy(req_type, "POST"); 
    }else if(session->request_type == REQ_TYPE_HEAD){
        strcpy(req_type, "HEAD");
    }else{
        strcpy(req_type, "UNKNOWN");
    }
    printf("===============session dump==================\n");
    if(session->url_data){
        printf("=== url : %s\n",((struct url_s*)session->url_data)->url);
    }
    printf("=== request_type : %s\n", req_type);
    printf("=== req_data_buf : %s\n", session->req_data_buf);
    printf("=== req_data_len : %d\n", session->req_buf_len);
    printf("=== req_head_buf : %s\n", session->req_head_buf);
    printf("=== req_head_len : %d\n", session->req_head_len);
    printf("=== req_head_len : %d\n", session->req_head_len);
    printf("=== rep_data_buf : %s\n", session->rep_data_buf);
    printf("=== rep_head_buf : %s\n", session->rep_head_buf);
}

char *get_url_path_from_packet(char *data, int datalen, char *url, char* fullpath)
{

    char *httpData = data;
    if(httpData == NULL) return NULL;

    int http_len = datalen;
    if(http_len <= 0)  return NULL;
    char path_tmp[512]="";
    
    if ((memcmp(httpData, "GET", 3) != 0) && (memcmp(httpData,"POST", 4) != 0))  return NULL;

    char *pFindEnd = strstr(httpData,"\r");
    if (pFindEnd != NULL)
    {
        int tmpLen = (pFindEnd - httpData) - 4 - 9;
        if ( tmpLen <= 0 )  
            return NULL;

        /* if url len too long, set it MAX_URL_LEN */
        if ( tmpLen >  MAX_URL_LEN)
        {
            tmpLen = MAX_URL_LEN;
        }
        
        if (memcmp(httpData, "GET", 3) == 0)
            strncpy(path_tmp, httpData+4,tmpLen); 
        else
            strncpy(path_tmp, httpData+5,tmpLen);
        
        //some .gif have content
        if (!((strcasestr(path_tmp, ".gif" ) != NULL)
            || (strcasestr(path_tmp, ".jpg") != NULL)
            || (strcasestr(path_tmp,".JPG") != NULL)
            || (strcasestr(path_tmp,".css") != NULL)
            || (strcasestr(path_tmp, ".zip") != NULL)
            || (strcasestr(path_tmp, ".exe") != NULL)
            || (strcasestr(path_tmp, ".mp") != NULL)
            || (strcasestr(path_tmp, ".flv") != NULL)
            || (strcasestr(path_tmp, ".ico") != NULL)
            || (strcasestr(path_tmp, ".gz") != NULL)
            || (strcasestr(path_tmp, ".swf") != NULL)
            || (strcasestr(path_tmp, ".cgi") != NULL)
            || (strcasestr(path_tmp,".png") != NULL)))
        {
            char *pHost = strstr(httpData, "Host");
            if(pHost == NULL)  return NULL;

            char *pHostEnd = strstr(pHost, "\r");
            if(pHostEnd != NULL)
            {
                int nHostLen = (pHostEnd - pHost) - 6;
                if((nHostLen <= 0 ) || (nHostLen > 398))  return NULL;

                strncpy(url,pHost+6,nHostLen);
                strncpy(fullpath,pHost+6,nHostLen);
                if(strcmp(path_tmp, "/"))
                    strncpy(fullpath+nHostLen,path_tmp,tmpLen);
                if(url[strlen(url)] == '/')
                    url[strlen(url)] = '\0';
                if(fullpath[strlen(fullpath)] == '/')
                    fullpath[strlen(fullpath)] = '\0';

                return url;
            }
        }

    }

    return NULL;
}


int url_filter(char *match, int datalen, struct session_t *session, int sn)
{
    char * pos = NULL;
    char       url[512]={0};
    char       fullpath[512]={0};
    unsigned int time_now = time(0);
    struct url_s *url_tmp=NULL;

    if(get_url_path_from_packet(match, datalen, url, fullpath) == NULL)
        return 0;

    if(strlen(fullpath) != 0)
    {
        //printf("Get Url:%s\n",fullpath);
        url_tmp = (struct url_s *)malloc(sizeof(struct url_s)+strlen(fullpath)+1);//no free for now; will freed when prog restart
        if(url_tmp == NULL){
            return NULL;
        }
        memset(url_tmp, 0, sizeof(struct url_s)+strlen(fullpath)+1);
        strcpy(url_tmp->url, fullpath);
        session->url_data = (char*)url_tmp;
        
        return 1;
    }
    return 0;
    
}

