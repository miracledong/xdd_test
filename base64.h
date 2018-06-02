// base64.h

//************************************************************************/
//    base64编码表
// 
//		0 A 17 R 34 i 51 z 
//		1 B 18 S 35 j 52 0 
//		2 C 19 T 36 k 53 1 
//		3 D 20 U 37 l 54 2 
//		4 E 21 V 38 m 55 3 
//		5 F 22 W 39 n 56 4 
//		6 G 23 X 40 o 57 5 
//		7 H 24 Y 41 p 58 6 
//		8 I 25 Z 42 q 59 7 
//		9 J 26 a 43 r 60 8 
//		10 K 27 b 44 s 61 9 
//		11 L 28 c 45 t 62 + 
//		12 M 29 d 46 u 63 / 
//		13 N 30 e 47 v (pad) = 
//		14 O 31 f 48 w 
//		15 P 32 g 49 x 
//		16 Q 33 h 50 y 
//
// base64编码步骤：
// 
//		原文：
//
//		你好
//		C4 E3 BA C3
//		11000100 11100011 10111010 11000011
//		00110001 00001110 00001110 00111010
//		49       14							（十进制）
//		x        O        O        6		字符
//		01111000 01001111 01001111 00110110
//		78									（十六进制）
//		xOO6
//
//		解码：
//		xOO6
//		78 4f 4f 36
//		01111000 01001111 01001111 00110110
//		49       14 
//		00110001 00001110 00001110 00111010   31 0e 0e 3a
//
//		11000100 11100011 10111010
//		C4       E3       BA
//

//#ifndef _BASE64_INCLUDE__H__
//#define _BASE64_INCLUDE__H__
#ifndef __BASE64_H__
#define __BASE64_H__
#include <arpa/inet.h> 
// 编码后的长度一般比原文多占1/3的存储空间，请保证base64code有足够的空间
inline int Base64Encode(unsigned char * base64code, const unsigned char * src, int src_len); 
inline int Base64Decode(unsigned char * buf, const unsigned char * base64code, int src_len);

__inline char GetB64Char(int index)
{
	const char szBase64Table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	if (index >= 0 && index < 64)
		return szBase64Table[index];
	
	return '=';
}

// 从双字中取单字节
#define B0(a) (a & 0xFF)
#define B1(a) (a >> 8 & 0xFF)
#define B2(a) (a >> 16 & 0xFF)
#define B3(a) (a >> 24 & 0xFF)


#define big_little(x)\
	((x)&0x000000ff) << 24|\
	((x)&0x0000ff00) << 8|\
	((x)&0x00ff0000) >> 8|\
	((x)&0xff000000) >> 24\

// 编码后的长度一般比原文多占1/3的存储空间，请保证base64code有足够的空间
inline int Base64Encode(unsigned char * base64code, const unsigned char * src, int src_len) 
{   
	int i,j;
	if (src_len == 0)
		src_len = strlen(src);
//printf("len:%d\n", src_len);	
	int len = 0;
	unsigned char* psrc = (unsigned char*)src;
	unsigned char * p64 = base64code;
	unsigned char ulTmp[3];
	for (i = 0; i < src_len - 3; i += 3)
	{
//		unsigned long ulTmp = *(unsigned long*)psrc;
//		ulTmp = big_little(ulTmp);
		memcpy(ulTmp, psrc, 3);
		register int b0 = GetB64Char((ulTmp[0] >> 2) & 0x3F); 
		register int b1 = GetB64Char((ulTmp[0] << 6 >> 2 | ulTmp[1] >> 4) & 0x3F); 
		register int b2 = GetB64Char((ulTmp[1] << 4 >> 2 | ulTmp[2] >> 6) & 0x3F); 
		register int b3 = GetB64Char((ulTmp[2] << 2 >> 2) & 0x3F); 
		p64[0] = b0;
		p64[1] = b1;
		p64[2] = b2;
		p64[3] = b3;
	
		len += 4;
		p64  += 4; 
		psrc += 3;
	}
	
	// 处理最后余下的不足3字节的饿数据
	if (i < src_len)
	{
		int rest = src_len - i;
		unsigned char ulTmp[3] = "";
		for (j = 0; j < rest; ++j)
		{
			ulTmp[j] = *psrc;
			psrc++;
		}
		
		p64[0] = GetB64Char((ulTmp[0] >> 2) & 0x3F); 
		p64[1] = GetB64Char((ulTmp[0] << 6 >> 2 | ulTmp[1] >> 4) & 0x3F); 
		p64[2] = rest > 1 ? GetB64Char((ulTmp[1] << 4 >> 2 | ulTmp[2] >> 6) & 0x3F) : '='; 
		p64[3] = rest > 2 ? GetB64Char((ulTmp[2] << 2 >> 2) & 0x3F) : '='; 
		p64 += 4; 
		len += 4;
	}
	
	*p64 = '\0'; 
	
	return len;
}


__inline int GetB64Index(char ch)
{
	int index = -1;
	if (ch >= 'A' && ch <= 'Z')
		index = ch - 'A';
	else if (ch >= 'a' && ch <= 'z')
		index = ch - 'a' + 26;
	else if (ch >= '0' && ch <= '9')
		index = ch - '0' + 52;
	else if (ch == '+')
		index = 62;
	else if (ch == '/')
		index = 63;
	else if(ch == '=')
		index = 0;
	return index;
}



	



// 解码后的长度一般比原文少用占1/4的存储空间，请保证buf有足够的空间
inline int Base64Decode(unsigned char * buf, const unsigned char * base64code, int src_len) 
{   
	int i,j;

	if (src_len == 0)
		src_len = strlen(base64code);

	int len = 0;
	unsigned char* psrc = (unsigned char*)base64code;
	unsigned char * pbuf = buf;
	unsigned char ulTmp[4] = "";
	for (i = 0; i < src_len - 4; i += 4)
	{
//		unsigned long ulTmp = *(unsigned long*)psrc;
//		ulTmp = big_little(ulTmp);
		memcpy(ulTmp, psrc, 4);
		register int b0 = (GetB64Index(ulTmp[0]) << 2 | GetB64Index(ulTmp[1]) << 2 >> 6) & 0xFF;
		register int b1 = (GetB64Index(ulTmp[1]) << 4 | GetB64Index(ulTmp[2]) << 2 >> 4) & 0xFF;
		register int b2 = (GetB64Index(ulTmp[2]) << 6 | GetB64Index(ulTmp[3]) << 2 >> 2) & 0xFF;
		
		//*((unsigned long*)pbuf) = b0<<8 | b1 << 16 | b2 << 24;
		pbuf[0] = b0;
		pbuf[1] = b1;
		pbuf[2] = b2;
		
		psrc  += 4; 
		pbuf += 3;
		len += 3;
	}

	// 处理最后余下的不足4字节的饿数据

	if (i < src_len)
	{
		int rest = src_len - i;
		unsigned char ulTmp[4] = "";
		for (j = 0; j < rest; ++j)
		{
			ulTmp[j] = *psrc;
			psrc++;
		}
		
		register int b0 = (GetB64Index(ulTmp[0]) << 2 | GetB64Index(ulTmp[1]) << 2 >> 6) & 0xFF;
		*pbuf = b0;
		pbuf++;
		len  ++;

		if ('=' != ulTmp[1] && '=' != ulTmp[2])
		{
			register int b1 = (GetB64Index(ulTmp[1]) << 4 | GetB64Index(ulTmp[2]) << 2 >> 4) & 0xFF;
			*pbuf++ = b1;
			len  ++;
		}
		
		if ('=' != ulTmp[2] && '=' != ulTmp[3])
		{
			register int b2 = (GetB64Index(ulTmp[2]) << 6 | GetB64Index(ulTmp[3]) << 2 >> 2) & 0xFF;
			*pbuf = b2;
			pbuf++;
			len++;
		}

	}
		
	*pbuf = '\0'; 
	
	return len;
} 

#endif // #ifndef _BASE64_INCLUDE__H__



