#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#include "sniffer_data.h"

//struct thread_manage *snf_data_arry;
#if 0
int malloc_sniffer_buffer(struct thread_manage *snf_data_arry, int arry_size)
{
    int i = 0;
    int res = 0;

    if (arry_size < 1)
        return -1;

    for (i = 0; i < arry_size; i++)
    {
        snf_data_arry->snf_data[i].buffer = (unsigned char *) malloc(SNF_BUF_SIZE);
	//	memset(&(snf_data_arry->snf_data[i].buffer),0,SNF_BUF_SIZE);
        res = pthread_mutex_init(&(snf_data_arry->snf_data[i].mutex), NULL);
        if (res != 0)
        {
            printf("Create %d pthread_mutex_init fail\n");
            break;
        }
    }

    return res;
}
#endif
int malloc_sniffer_buffer(struct sniffer_data* sniffer_data, int arry_size)
{
	int i = 0;
	int res = 0;

	if (arry_size < 1)
		return -1;

	for (i = 0; i < arry_size; i++)
	{
		sniffer_data[i].buffer = (unsigned char *) malloc(SNF_BUF_SIZE);

		res = pthread_mutex_init(&sniffer_data[i].mutex, NULL);
		if (res != 0)
		{
			printf("Create %d pthread_mutex_init fail\n");
			break;
		}
	}

	return res;
}
