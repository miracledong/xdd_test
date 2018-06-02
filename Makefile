OBJS = filter.o 
#OBJS += block.o analysis_pack.o sniffer_send_redirect.o send_packet.o communicate.o  sniffer_data.o sniffer_util.o send_util.o get_configure.o create_sock.o
#OBJS += tool.o handle_mem.o handle_tcp.o sniffer_util.o des.o handle_app.o session.o decrypt.o encrypt.o sniffer_data.o ip_list.o analysis_pack.o sniffer_send_redirect.o send_packet.o communicate.o send_util.o get_configure.o create_sock.o epoll_server.o thread_process_function.o
OBJS += tool.o cJSON.o util.o handle_mem.o handle_tcp.o sniffer_util.o des.o handle_app.o session.o decrypt.o encrypt.o sniffer_data.o ip_list.o analysis_pack.o sniffer_send_redirect.o send_packet.o communicate.o send_util.o get_configure.o create_sock.o epoll_server.o thread_process_function.o 
#OBJS += tool.o cJSON.o  handle_mem.o handle_tcp.o sniffer_util.o des.o handle_app.o session.o decrypt.o encrypt.o sniffer_data.o ip_list.o analysis_pack.o sniffer_send_redirect.o send_packet.o communicate.o send_util.o get_configure.o create_sock.o epoll_server.o thread_process_function.o 
LIBS = -lm -lrt 
LIBS += -lpthread-0.9.33.221  
#CC=mips-openwrt-linux-uclibc-gcc
CC=mips-linux-uclibc-gcc
#CFLAGS = -Wall -I. -I/home/yanliang/openwrt-sdk/staging_dir/toolchain-mips_r2_gcc-4.6-linaro_uClibc-0.9.33.2/include/
CFLAGS = -Wall -I. -L/home/edu/maipu/hndtools-mips-linux-2.6.31-uclibc-4.3.6/include
#CFLAGS += -I/home/yanliang/openwrt-sdk/staging_dir/target-mips_r2_uClibc-0.9.33.2/usr/lib/libnet-1.1.x/include/
#LDFLAGS = -L/home/edu/maipu/hndtools-mips-linux-2.6.31-uclibc-4.3.6/lib
LDFLAGS = -L/home/edu/maipu/audit_com/
#LDFLAGS += -L./libnet 
#CFLAGS += -DWE_CHAT
#LDFLAGS = -L/home/yanliang/openwrt-sdk/staging_dir/toolchain-mips_r2_gcc-4.6-linaro_uClibc-0.9.33.2/lib/ 
#LDFLAGS += -L/home/yanliang/openwrt-sdk/staging_dir/target-mips_r2_uClibc-0.9.33.2/usr/lib/libnet-1.1.x/lib/
#LDFLAGS += -DLITTLE_EN
#LDFLAGS += -DBAIMI
#LDFLAGS += -DNO_OFFLINE
LDFLAGS += -DHAINAN_MODE
EXEC = url_audit
#default:$(EXEC)
%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@ 
all:$(EXEC)
$(EXEC):$(OBJS)
	 $(CC) $(CFLAGS) $(OBJS) -o  $@ $(LDFLAGS) $(LIBS) libpcap.a
clean:
	rm -f $(EXEC) $(OBJS)
