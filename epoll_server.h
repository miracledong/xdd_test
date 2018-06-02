#ifndef __EPOLL_SERVER_H__
#define __EPOLL_SERVER_H__
typedef struct
{
	char ip4[128];
	int port;
	int fd;
}listen_info;

typedef enum
{
	TLV_DATA_TYPE		= 0x01,
	TLV_REQUEST_TYPE	= 0x02,
	TCV_SSID_TYPE		= 0x03,
	TCV_STAMAC_TYPE		= 0x04,
	TLV_2EAPOL_TYPE		= 0x05,		//第二次握手包的eapol
	TLV_3EAPOL_TYPE		= 0x06,		//第三次握手包的eapol
	TCV_ANONCE_TYPE		= 0x07,		//anonce
	TCV_SNONCE_TYPE		= 0x08,		//snonce
	TCV_2KEYMIC_TYPE	= 0x09,		//2keymic
	TCV_3KEYMIC_TYPE	= 0x10,		//3keymic
	TCV_KEYVER_TYPE		= 0x11,		//keyver	
}TLV_PDU_ACK_TYPE;

typedef struct
{
	unsigned char index[2];
	unsigned char devicenumber[14];
	uint8_t type; 
	unsigned char bssid[6];  
	uint16_t length;
}PDU_HEAD;

typedef struct
{
	uint8_t type;
	uint16_t length;
}TLV_HEAD_RULE;

typedef struct
{
	uint8_t type;
	uint16_t length;
	unsigned char stmac[6];  
}TLV_STMAC_RULE;

typedef struct
{
	uint8_t type;
	uint16_t length;
	unsigned char anonce[32]; 
}TLV_ANONCE_RULE;

typedef struct
{
	uint8_t type;
	uint16_t length;
	unsigned char snonce[32];  
}TLV_SNONCE_RULE;

typedef struct
{
	uint8_t type;
	uint16_t length;
	unsigned char keymic2[20]; //第二次握手包的mic
}TLV_2KEYMIC_RULE;

typedef struct
{
	uint8_t type;
	uint16_t length;
	unsigned char keymic3[20];   //第三次握手包的mic
}TLV_3KEYMIC_RULE;

typedef struct
{
	uint8_t type;
	uint16_t length;
	int keyver;    //加密方式  
}TLV_KEYVER_RULE;

#endif
