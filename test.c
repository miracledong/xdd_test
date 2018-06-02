/* ************************************************************************
 *       Filename:  test.c
 *    Description:  
 *        Version:  1.0
 *        Created:  2016年07月22日 18时06分46秒
 *       Revision:  none
 *       Compiler:  gcc
 *         Author:  YOUR NAME (), 
 *        Company:  
 * ************************************************************************/

#include <stdio.h>
#include <stdlib.h>
void  get_network_ip(char *cmd)
{	
	char ip_net[100] = "";
	char buf[100] = "";   	
	FILE *ptr;   	
	if((ptr=popen(cmd, "r"))!=NULL){   		
		fgets(buf, 1024, ptr);   			
		pclose(ptr);   		
		ptr = NULL;   		
		char *p = buf;		
		p += 3;		
		strcpy(ip_net,p);	
	}else		
		printf("popen %s error\n", cmd);   	
	if(strlen(ip_net))
		printf("%s\n",ip_net);
	return;
}
int main()
{
	get_network_ip("curl http://www.ip.cn/index.php?ip=218.61.33.47");
	return ;
	}


