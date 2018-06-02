
#include "handle_mem.h"

#include <string.h>
#include <stdio.h>

char *memstr(char *buf, int len, char *substr)
{
    	int subLen = 0;
	int reLen = 0;
	char * index = NULL;
	char serLen = 0;
	char *midbuf;

	if (buf == NULL || len == 0 || substr == NULL)
		return NULL;
	
	subLen = strlen(substr);

	if (len < subLen)
		return NULL;

	reLen = len;
	midbuf = buf;

	while(reLen > subLen)
	{
		index = memchr(midbuf, substr[0], reLen);
		if (index == NULL)
			return NULL;
		
		if (memcmp(index, substr, subLen) == 0)
			return index;	
		
		serLen = index -buf;
		midbuf = index;

		if (serLen < len)
		{
			midbuf++;
			serLen++;
		}

		reLen = len - serLen;
	}

	return NULL;
}

#if 0
int main(void)
{
	char *str = "stonezhangerae\r\nfaaaaeeqrq";
	char *index = NULL;
	char len = strlen(str);

	index = memstr(str, strlen(str), "zhang");
	if (index != NULL)
		printf("index = %s\n", index);
	else 
		printf("index is null\n");

	index = memstr(str, strlen(str), "st");
	if (index != NULL)
		printf("index = %s\n", index);
	else 
		printf("index is null\n");

	index = memstr(str, len, "kelx111111111111111111111111111111111111111111");
	if (index != NULL)
		printf("index = %s\n", index);
	else 
		printf("index is null\n");

	index = memstr(str, strlen(str), "\r\n");
	if (index != NULL)
		printf("index = %s\n", index);
	else 
		printf("index is null\n");

	return 0;
	 
}
#endif
