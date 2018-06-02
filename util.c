#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>
/*#include <iconv.h>
int code_convert(char *from_charset,char *to_charset,char *inbuf,size_t *inlen,char *outbuf,size_t *outlen)
{
	iconv_t cd;
	int rc;
	char **pin = &inbuf;
	char **pout = &outbuf;

	cd = iconv_open(to_charset,from_charset);
	if (cd==0) return -1;
	memset(outbuf,0,*outlen);
	rc=iconv(cd,pin,inlen,pout,outlen);
	iconv_close(cd);
	return rc;
}

int u2g(char *inbuf,size_t *inlen,char *outbuf,size_t *outlen)
{
	return code_convert("utf-8","gb2312",inbuf,inlen,outbuf,outlen);
}

int gbk2g(char *inbuf,size_t *inlen,char *outbuf,size_t *outlen)
{
	return code_convert("gbk","gb2312",inbuf,inlen,outbuf,outlen);
}

int g2u_new(char *inbuf,size_t* inlen,char *outbuf,size_t* outlen)
{
	return code_convert("gb2312","utf-8",inbuf,inlen,outbuf,outlen);
}

int unicode2u8(char *inbuf,size_t *inlen,char *outbuf,size_t *outlen)
{
	return code_convert("WCHAR_T","utf-8",inbuf,inlen,outbuf,outlen);
}

int gbk2u8(char *inbuf,size_t *inlen,char *outbuf,size_t *outlen)
{
	return code_convert("gbk","utf-8",inbuf,inlen,outbuf,outlen);
}*/


int unicode_urldecode(char* str, int len){

    //鍙傛暟鍒ゆ柇
    if(!str || len < 0){
        return -1;
    }
    //鍑芥暟鐜鍒濆鍖?
    char *ptr = str;
    char *buffer = (char*)calloc(len*2, sizeof(char));
    if(!buffer){
        return -1;
    }
    char *buffer_ptr = buffer;
    int flag = 0;
    char unit[5] = {'\0'};
    char *unit_ptr = NULL;
    unit_ptr = unit;
    char tmp[10] = {0};

    //鍑芥暟涓氬姟閫昏緫寮€濮?
    while(ptr < (str + len) && *ptr != '\0'){
    
        if(*ptr == '%'){
            if(*(ptr+1) == 'u'){
                ptr++;
                flag = 1;
            }else{
                return -1;
            }
            flag = 1;
        
        }else{
            
            if(flag){
                //瀛楃涓叉浛鎹?
                *unit_ptr++ = *ptr;
                if(strlen(unit) >= 4){
                    //1.杞崲涓哄搴旂殑鏃犵鍙锋暟
                    unsigned short int num = (unsigned short int)strtol(unit, NULL, 16);
                    //2.灏嗗瓧绗﹁浆鎹负utf-8瀛楃
                    size_t inlen = 2;
                    size_t outlen = 10;
                    //code_convert("unicode","utf-8",(char*)&num, &inlen, tmp, &outlen);
                    memcpy(buffer_ptr, tmp, strlen(tmp));
                    buffer_ptr += strlen(tmp);
                    //3.灏嗘寚閽堝拰鏍囧織澶嶅師
                    unit_ptr = unit;
                    flag = 0;
                    memset(unit, 0, 5);
                }

            }else{
                //鍘熸牱澶嶅埗
                *buffer_ptr++ = *ptr;
            }
        }

        ptr++;
    }

    int new_len = strlen(buffer) > len ? len : strlen(buffer);
    memset(str, 0, len);
    memcpy(str, buffer, new_len);
    
    //杩斿洖
    free(buffer);
    buffer = NULL;

    return new_len;
}
