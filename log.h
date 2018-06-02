#ifndef __LOG_H__
#define __LOG_H__

#include "zlog.h"

extern zlog_category_t  *my_cat;


void init_zlog_config();

#define LOG_INIT() do{ init_zlog_config(); }while(0)

#define LOG_DEBUG(format, args...) \
	do{ zlog_debug(my_cat, format, ##args);}while(0)
#define LOG_INFO(format, args...) \
	do{ printf(format, ##args);}while(0)
#endif
