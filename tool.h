/* ************************************************************************
 *       Filename:  tool.h
 *    Description:  
 *        Version:  1.0
 *        Created:  2016年09月08日 16时03分23秒
 *       Revision:  none
 *       Compiler:  gcc
 *         Author:  YOUR NAME (), 
 *        Company:  
 * ************************************************************************/

#ifndef __TOOL_H__
#define __TOOL_H__
int readfile_get_mac(char *src_ip,char *mac);
int host_to_ip(char *hostname,char *ip_config);
void check_curl(char *cmd,char *response,int len);
void send_real_login(char *ip_src,char *mac_with_colon,char *phonenum);
#endif


