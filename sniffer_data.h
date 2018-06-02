#ifndef __SNIFFER_DATA_
#define __SNIFFER_DATA_

#include <pthread.h>
#include "list.h"
#define SNF_BUF_SIZE 1518
#define SNF_ARRY_SIZE 2000
struct sniffer_data
{
   unsigned char *buffer;
   int data_size; // recv data size
   int type;
   pthread_mutex_t mutex;
};

struct thread_manage
{
	struct list_head head;
	pthread_t pthread;
	unsigned int packet_need_to_deal;
	unsigned int packet_index;
	struct sniffer_data snf_data[SNF_ARRY_SIZE]; 
};
//int malloc_sniffer_buffer(struct thread_manage *snf_data_arry, int arry_size);
int malloc_sniffer_buffer(struct sniffer_data* sniffer_data, int arry_size);
#endif
