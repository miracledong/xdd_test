#ifndef IP_LIST_H
#define IP_LIST_H

#define  DEL_IP_TIME  30

struct ip_list
{
	char ip[20];
	time_t  time;
	struct ip_list *next;
};


//遍历链表 寻找MAC
struct ip_list *ergodic_ip_list(struct ip_list  *head,char *ip);

//把MAC地址加入链表
void  add_ip_list( struct ip_list  **p_head, struct ip_list *p_new); //插入链表


//删除过期的节点

void link_delete_ip(struct ip_list **p_head);

#endif 




