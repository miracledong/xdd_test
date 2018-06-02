#ifndef IP_LIST_H
#define IP_LIST_H

#define  DEL_IP_TIME  30

struct ip_list
{
	char ip[20];
	time_t  time;
	struct ip_list *next;
};


//�������� Ѱ��MAC
struct ip_list *ergodic_ip_list(struct ip_list  *head,char *ip);

//��MAC��ַ��������
void  add_ip_list( struct ip_list  **p_head, struct ip_list *p_new); //��������


//ɾ�����ڵĽڵ�

void link_delete_ip(struct ip_list **p_head);

#endif 




