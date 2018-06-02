#ifndef __HANDLE_TCP_H__
#define __HANDLE_TCP_H__
#include "passenger_info.h"
struct iphdr;
struct tcphdr;
struct udphdr;

void handle_tcp(struct udphdr *udphptr, int data_len, struct panssenger_info* passenger_info);



#endif
