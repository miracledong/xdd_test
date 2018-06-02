#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <pthread.h>
#include <errno.h>

#include "epoll_server.h"
/*线程池的线程数量*/
#define THREAD_MAX 100
extern pthread_mutex_t s_mutex[THREAD_MAX];//线程锁

pid_t start_crack_passwd(char *buff)
{
	pid_t pid,pid1;
	pid = fork();
	if(pid == 0)
	{
		pid1 = fork();
		if (pid1 == 0)
		{
			char *args[3];
			args[0] = "crack_passwd";
			args[1] = buff;
			args[2] = NULL;
			execv("./crack_passwd",args);
			exit(0);
		}
		else
			exit(0);
	}
	if(waitpid(pid, NULL, 0) != pid)
		printf("++++++++++++line:%d fork error\n", __LINE__);
	return pid;
}

static int topport = 50000; //50000 - 65000 
pid_t start_check_passwd(char *buff)
{
	pid_t pid,pid1;
	char string[8] = "";
	sprintf(string,"%d",topport++);
	printf("topport == %d\n",topport);
	pid = fork();
	if(pid == 0)
	{
		pid1 = fork();
		if (pid1 == 0)
		{
			if(topport > 65000)
				topport = 50000;
			char *args[4];
			args[0] = "check_passwd";
			args[1] = buff;
			args[2] = strdup(string);
			args[3] = NULL;
			execv("./check_passwd",args);
			exit(0);
		}
		else
			exit(0);
	}
	if(waitpid(pid, NULL, 0) != pid)
		printf("++++++++++++line:%d fork error\n", __LINE__);
	return pid;
}

void * thread_process_function(unsigned int thread_para[])
{
	//临时变量
	int pool_index = thread_para[1];	//线程池索引
	char *p = (char *)thread_para[2];
		//线程脱离创建者
	pthread_detach(pthread_self());
wait_unlock:
	pthread_mutex_lock(s_mutex + pool_index);//等待线程解锁
//	printf("recv package\n");
	analysis_pack(p);
	//线程任务结束
	thread_para[0] = 0;//设置线程占用标志为"空闲"
	goto wait_unlock;

	pthread_exit(NULL);
}
