#ifndef __SNIFFER_DEF_H
#define __SNIFFER_DEF_H

#define MAX_WEB_LEN	40
#define MAX_FOLDER_LEN	56
#define MAX_LIST_NUM	100

#define URL_COUNT 100
#define ENTRY_SIZE 256
#define LOG_TIMEOUT 10

typedef struct _URL{
	char website[MAX_WEB_LEN];
	char folder[MAX_FOLDER_LEN];
	char lanIP[16];
	struct _URL *next;
}URL, *PURL;

extern PURL purl;

#include "list.h"
#include "passenger_info.h"

struct pc_t 
{
	struct list_head head;
	u_int32_t src_ip;
	struct panssenger_info passenger_info;
};


#endif
