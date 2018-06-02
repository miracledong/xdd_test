#include "log.h"

zlog_category_t  *my_cat;

void init_zlog_config()
{
	int rc;
	//zlog_category_t *c;

	rc = zlog_init("/var/tmp/disk/mmcblk0/user/boyi_app/zlog.conf");
	if (rc) {
		LOG_DEBUG("init failed\n");
	}
	my_cat = zlog_get_category("my_cat");

	if (!my_cat) {
		LOG_DEBUG("get cat fail\n");
		zlog_fini();
	}
}
