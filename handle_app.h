#ifndef __HANDLE_APP_H__
#define __HANDLE_APP_H__
#include "passenger_info.h"
#include "session.h"
struct iphdr;
struct tcphdr;
#define IMEI_LEN  15
#define IMSI_LEN_MAX 15
#define IMSI_LEN_MIN 3
#define DIDI_LEN  11


void handle_app(char* data,struct session_t *session, struct panssenger_info* passenger_info);
void get_weixin_login(char *data,int data_len,struct panssenger_info *passenger_info);

#endif
