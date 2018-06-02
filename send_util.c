#include "passenger_info.h"
#include <stdio.h>

void add_login_data_to_passenger(struct login_data_list_s *login_data_list, struct panssenger_info *passenger_tmp)
{
	login_data_list->next = (char*)passenger_tmp->login_list;
	passenger_tmp->login_list = login_data_list;
	return;
}


struct login_data_list_s * find_login_data_by_id_type(char *ID, char *ID_type, struct panssenger_info *passenger_tmp)
{
	struct login_data_list_s *login_data_list_tmp = NULL;
//	struct login_s *login_data_tmp = NULL;
	struct virtual_info *login_data_tmp = NULL;
	if(passenger_tmp)
		login_data_list_tmp = passenger_tmp->login_list;
	
	if(login_data_list_tmp && login_data_list_tmp->login_data)
		login_data_tmp = (struct virtual_info *)login_data_list_tmp->login_data;

	while(login_data_tmp)
	{
		//printf("login_list:%s %s|\n",login_data_tmp->id,login_data_tmp->id_type);
		if(login_data_tmp && login_data_tmp->id && login_data_tmp->id_type && !strcasecmp(ID, login_data_tmp->id) && !strcmp(ID_type, login_data_tmp->id_type))
			return login_data_list_tmp;
		login_data_tmp = NULL;
		login_data_list_tmp = (struct login_data_list_s*)login_data_list_tmp->next;
		if(login_data_list_tmp && login_data_list_tmp->login_data)
			login_data_tmp = (struct virtual_info *)login_data_list_tmp->login_data;
	}
	return NULL;
}

free_passenger_data(struct panssenger_info *passenger_tmp)
{
#if 0
	struct login_data_list_s *login_list = passenger_tmp->login_list;
	struct login_data_list_s *login_list_tmp=passenger_tmp->login_list;
	while(login_list_tmp)
	{
		login_list = login_list_tmp;
		//printf("%s|%s|\n",((struct login_s*)login_list_tmp->login_data)->id,((struct login_s*)login_list_tmp->login_data)->id_type);
		free_sent_data((char **)login_list->login_data ,sizeof(struct login_s)/sizeof(char*));
		free(login_list->login_data);
		login_list->login_data=NULL;

		login_list_tmp = (struct login_data_list_s*)login_list_tmp->next;
		free(login_list);
		login_list=NULL;
	}

    if (passenger_tmp->telnet_data)
        free(passenger_tmp->telnet_data);
	//free(passenger_tmp);
	#endif
}

