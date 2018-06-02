#ifndef __SNIFFER_UTIL_H
#define __SNIFFER_UTIL_H

void AEI_get_lan_ip(char *addr);
void AEI_get_lan_macaddr(char *addr);
char *get_url_path_from_packet(char *data, int datalen, char *url, char* fullpath);

int get_content_data(char* src,char* start,char* end,char* target,int limit);
#define  MAX_URL_LEN 256

#endif



