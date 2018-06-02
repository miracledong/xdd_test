#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "ip_list.h"

//¿¿¿¿¿¿¿¿¿MAC
struct ip_list *ergodic_ip_list(struct ip_list *head,char *ip)
{
 	struct ip_list *p_mov;
	p_mov = head;
	while(p_mov)
	{
		if(strcmp(p_mov->ip,ip) == 0)//¿¿MAC
		{
			return p_mov;
		}
		p_mov = p_mov->next;
	}
	return NULL;
}

//¿MAC¿¿¿¿¿¿¿¿
void  add_ip_list( struct ip_list  **p_head, struct ip_list *p_new) 
{
	 struct ip_list  *p_mov=*p_head;
	if(*p_head == NULL) //¿¿¿¿NULL¿
		*p_head = p_new;
	else	//¿¿¿¿¿NULL¿
	{		
		while(p_mov->next)
			p_mov = p_mov->next;	//¿¿¿¿¿¿¿¿
		p_mov->next = p_new;		//¿¿¿¿¿¿
	}
	p_new->next = NULL;
	return;
}

//¿¿¿¿¿¿

void link_delete_ip(struct ip_list **p_head)
{
	time_t time_now = time(0);
	struct ip_list *pb,*pf;
	char cmd[32] = {'\0'};
	pb = pf = *p_head;
	if(*p_head == NULL)//¿¿¿¿¿¿¿¿
		return ;
	while(pb)//¿¿¿¿¿¿¿
	{	
		if((time_now - pb->time) >= DEL_IP_TIME)//¿¿¿¿¿¿¿¿¿¿¿
		{
printf("----%s:%d---\n",__FILE__,__LINE__);
			//sprintf(cmd,"sh ./refuse_ip.sh %s",pb->ip);
			//system(cmd);

printf("----%s:%d---\n",__FILE__,__LINE__);
			if(pb == *p_head)//¿¿¿¿¿
			{
				*p_head = pb->next;
				pf = *p_head;
			}
			else //¿¿¿¿¿¿
			{
				pf->next = pb->next;
			}
			free(pb);//¿¿¿¿¿¿¿¿¿
			pb = pf;//¿¿¿¿¿¿¿¿¿¿
			printf("del mac ok\n");
			continue;
		}
		else //¿¿¿¿¿¿¿¿¿¿¿¿¿¿
		{
			pf = pb;
		}
		pb = pb->next;		
	}
	return;
}






