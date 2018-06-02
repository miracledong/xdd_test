#ifndef SESSION_H__
#define SESSION_H__
#include <stdio.h>
#include <stdlib.h>

#define MAX_PARSE_PKT_COUNT 160//if a session have communicated over 16 packet, give up to parse, it usually is BT flow
#define MAX_PARSE_BUF_SIZE 35536 //64K
#define PROTO_MAX_PARSE_BUF_SIZE 8192 // 8K
#define MIN_PARSE_BUF_SIZE 2048 // 2k
#define MAX_COOKE_BUF_SIZE 2048 //2k
#define MAX_USER_AGENT_SIZE 256 //256
#define MAX_REFER_SIZE 256 //256

#define SESSION_TIMEOUT 5

#define UNKNOWN_TYPE 0x1
#define HTTP_TYPE 0x2
#define OTHER_TYPE 0x4

#define WEB_PORT 80
#include "list.h"

#define GET_METHOD 0
#define POST_METHOD 1

#ifndef true
#define true 1
#endif
#ifndef false
#define false 0
#endif

typedef enum {
 SES_INIT = 1, /*session_t create*/
 SES_REQ, /*request stage*/
 SES_REP, /*response stage*/
 SES_OVER_BUF, /*Over MAX_PARSE_BUF_SIZE buf*/
 SES_OVER_PKT, /*Over MAX_PARSE_PKT_COUNT*/
 SES_FIN
} SessionStatus;

typedef enum {
        HTTP_COMPRESS_NONE = 0,
        HTTP_COMPRESS_GZIP,
        HTTP_COMPRESS_DEFLATE,
        HTTP_COMPRESS_COMPRESS,
        HTTP_COMPRESS_IDENTITY
}CompressType;

typedef enum {
 CON_TYPE_NONE = 0,
 CON_TYPE_TEXT,
 CON_TYPE_IMAGE_VIDEO_AUDIO,
 CON_TYPE_APP,
 CON_TYPE_OTHER
}ContentType;

typedef enum {
 REQ_TYPE_GET = 1,
 REQ_TYPE_POST,
 REQ_TYPE_HEAD
}ReqType;

enum type_limit{
 VISIT_HTTP = 0,
 VISIT_IP = 1,
 VISIT_POP3 = 2,
 VISIT_SMTP = 3,
 VISIT_FTP = 4,
 VISIT_TELNET = 5,
 VISIT_163MAIL = 6,
 VISIT_QQ = 7,
 VISIT_QQGAME = 8
};


struct session_t{
 struct list_head head;

 unsigned int srcip;
 unsigned int dstip;
 unsigned short srcport;
 unsigned short dstport;


 //virtual ID

 unsigned int timestamp;

 unsigned char type;
 unsigned int pkt_count;

 char  *key_word;

 char  *url_data;//point to assoiated url struct
 int  request_type;
 char charset[32];

 char *referer;//point to referer
 int refer_len;

 char *rep_data_buf; //response data
 int rep_buf_len; // response date buf len 
 char  *rep_head_buf; //response head
 int rep_head_len; // response head buf len
 int rep_content_len; // response Content-Length
 int rep_data_offset;
 int rep_head_offset;

 char *req_data_buf; // request data buf 
 int req_buf_len; //request date buf len 
 int req_head_completed;
 char  *req_head_buf; //include Get ,Post, head
 int req_head_len;  // request head buf len
 int req_content_len; // request Content-Length
 int req_data_offset;
 int req_head_offset;

 char *decode_buf; // uncompress data buffer
 int decode_len;

 char *cookie_buf;
 char *user_agent;
 int cookie_len;

 int curr_point;

 CompressType compress_type;
 SessionStatus ses_st; //session status
 ContentType content_type;
 _Bool keep_alive;
 _Bool chunked; // chunked transfer encoding
 _Bool   doUnCompressed; //uncompressed or not 
};

struct url_s
{
 struct list_head head;
 unsigned int hostip;

 unsigned char status;
 int visit_count;
 time_t last_visit_time;

 char *session_data;//point to assoiated session data


 char title[256];
 
 char url[0];// full path url, include file path if have
 
};

struct session_t * del_session_from_list(struct session_t *session);
struct session_t * do_session_filter(char *data, int sn);
void session_dump(struct session_t* session);
char *get_url_path_from_packet(char *data, int datalen, char *url, char* fullpath);
int url_filter(char *match, int datalen, struct session_t *session, int sn);

int init_session_filter_list();
#define  MAX_URL_LEN 256


#endif

