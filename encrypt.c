#include <stdio.h>
#include <string.h>
//#include <rpc/des_crypt.h>
#include <stdlib.h>
#include "./des.h"
//#include "./base64.h"
//#include "./encrypt.h"

#define BLOCK_SIZE 8

void cbc(unsigned char *, int, int, unsigned char *);
void fedprint( unsigned char *, int);
void s_des_encrypt( unsigned char * key,  unsigned char * iv, unsigned char * msg,int * size);
void s_des_decrypt( unsigned char * key,  unsigned char * iv,  unsigned char * msg, int size);
void t_des_encrypt( unsigned char * key,  unsigned char * key2, unsigned char * iv, unsigned char * msg,int * size);
void t_des_decrypt( unsigned char * key,  unsigned char * key2, unsigned char * iv, unsigned char * msg, int size);
void pad(char *, int *);


void url_decrypt(char *out, char *src)
{
 unsigned char key[8] = "wy$@tere";
 unsigned char iv[BLOCK_SIZE] = "salt#&@!";


 // unsigned char msg[100] = "+PzXFAqq4xsYueFlSWqpEw==";
 //unsigned char msg[1024] = "AF3PzRix20GykjOuKQd8X+Yb78GCJkcuMPsaUQ/oo+ha4q+wuBb82pBHBw9uPYTSLYB/wzdRvc4aoo214sjIMSqKn7JItXuWy0KS+Q2ueZEUvEvjCgZ3tpupfDHEZDxhhdwn5iljjWPaD/hE4fB/Ahp1qsPCqBViNRUvRr2W5ZQ4ge9QQWWw+g==";
 unsigned char msg[1024];
 unsigned char out1[1024];

 if (src == NULL || out == NULL)
   return;

 int size = strlen(src);

 memset(msg, '\0', 1024); 
 memset(out1, '\0', 1024); 

 strncpy(msg, src, size);

 des_setparity(key);

// printf("%s,%d\n",msg,size);

 Base64Decode(out1, msg, 0);

 s_des_decrypt(key,iv,out1, size);

// printf("Dec\n");
// fedprint(out1,size);
// printf("%s\n",out1);

 strncpy(out, out1, strlen(out1));

 return;

}

#if 0
void main()
{
   //char src[1024] = "vUSAx1YE2QRYGTr2/KColCmoJLqlZav5";
   unsigned char src[1024] = "AF3PzRix20GykjOuKQd8X+Yb78GCJkcuMPsaUQ/oo+ha4q+wuBb82pBHBw9uPYTSLYB/wzdRvc4aoo214sjIMSqKn7JItXuWy0KS+Q2ueZEUvEvjCgZ3tpupfDHEZDxhhdwn5iljjWPaD/hE4fB/Ahp1qsPCqBViNRUvRr2W5ZQ4ge9QQWWw+g==";
   char out[1024];

   url_decrypt(out, src);

   return;
}
 
 unsigned char key[8] = "by$@hdtv";
 unsigned char iv[BLOCK_SIZE] = "salt#&@!";
 unsigned char msg[1024] = "ZhangSto";
main(char* argv, int argc)
{

 unsigned char key[8] = "wy$@tere";
 unsigned char key2[8] = "12345678";
 des_setparity(key);
 des_setparity(key2);

// unsigned char msg[100] = "+PzXFAqq4xsYueFlSWqpEw==";
 unsigned char out[1024] = "";
  unsigned char msg[1024] = "AF3PzRix20GykjOuKQd8X+Yb78GCJkcuMPsaUQ/oo+ha4q+wuBb82pBHBw9uPYTSLYB/wzdRvc4aoo214sjIMSqKn7JItXuWy0KS+Q2ueZEUvEvjCgZ3tpupfDHEZDxhhdwn5iljjWPaD/hE4fB/Ahp1qsPCqBViNRUvRr2W5ZQ4ge9QQWWw+g==";
 unsigned char out1[1024];
 
 unsigned char iv[BLOCK_SIZE] = "salt#&@!";

 
 int size = strlen(msg);

printf("%s,%d\n",msg,size);

printf("out = %s\n", out);
Base64Decode(out1, msg, 0);


s_des_decrypt(key,iv,out1, size);

printf("Dec\n");
fedprint(out1,size);
printf("%s\n",out1);
return 0;
}

#endif
main2(char* argv, int argc)
{

 unsigned char key[8] = "wy$@tere";
 unsigned char key2[8] = "12345678";
 des_setparity(key);
 des_setparity(key2);

 unsigned char msg[100] = "Zhang Sto";
 unsigned char out[100] = "";
// unsigned char out[1024] = "AF3PzRix20GykjOuKQd8X+Yb78GCJkcuMPsaUQ/oo+ha4q+wuBb82pBHBw9uPYTSLYB/wzdRvc4aoo214sjIMSqKn7JItXuWy0KS+Q2ueZEUvEvjCgZ3tpupfDHEZDxhhdwn5iljjWPaD/hE4fB/Ahp1qsPCqBViNRUvRr2W5ZQ4ge9QQWWw+g==";
 unsigned char out1[1024];
 
 unsigned char iv[BLOCK_SIZE] = "salt#&@!";

 
 int size = strlen(msg)+1;

/*  if((size % BLOCK_SIZE) != 0){
	char * newmsg;
	int newsize = ((size/BLOCK_SIZE)+1)*BLOCK_SIZE;
	newmsg = malloc(newsize);
	memset(newmsg,'\0',newsize);
	strcpy(newmsg,msg);
	msg = newmsg;
	size = newsize;
  }*/

pad(msg,&size);
printf("%s,%d\n",msg,size);

printf("DES\n");
fedprint(msg,size);
s_des_encrypt(key,iv,msg,&size);

printf("Enc\n");
fedprint(msg,size);

Base64Encode(out, msg, 0);
printf("out = %s\n", out);
Base64Decode(out1, out, 0);


s_des_decrypt(key,iv,out1, size);

printf("Dec\n");
fedprint(out1,size);
printf("%s\n",out1);
#if 0
printf("T DES\n");
fedprint(msg,size);
t_des_encrypt(key,key2,iv,msg,&size);

fedprint(msg,size);
t_des_decrypt(key,key2,iv,msg,size);

fedprint(msg,size);
printf("%s\n",msg);
#endif
return 0;
}

void main1 (void)
{
 unsigned char key[8] = "by$@hdtv";
 unsigned char key2[8] = "12345678";
 des_setparity(key);
 des_setparity(key2);
 int size2 = 0;

 //unsigned char msg[1024] = "AF3PzRix20GykjOuKQd8X+Yb78GCJkcuMPsaUQ/oo+ha4q+wuBb82pBHBw9uPYTSLYB/wzdRvc4aoo214sjIMSqKn7JItXuWy0KS+Q2ueZEUvEvjCgZ3tpupfDHEZDxhhdwn5iljjWPaD/hE4fB/Ahp1qsPCqBViNRUvRr2W5ZQ4ge9QQWWw+g==";
 //unsigned char msg[1024] = "Wmg3yUD5EcXQR+2/AQ==";
// unsigned char msg[1024] = "7sSjcBCY1D1TN20Fvn6GSYTSug==";
 unsigned char msg[1024] = "ZhangSto";
 

 unsigned char out[1024] = "";
 unsigned char iv[BLOCK_SIZE] = "salt#&@!";

 
 int size = strlen(msg) + 1;

/*  if((size % BLOCK_SIZE) != 0){
	char * newmsg;
	int newsize = ((size/BLOCK_SIZE)+1)*BLOCK_SIZE;
	newmsg = malloc(newsize);
	memset(newmsg,'\0',newsize);
	strcpy(newmsg,msg);
	msg = newmsg;
	size = newsize;
  }*/

pad(msg,&size);
printf("%s,%d\n",msg,size);

cbc_crypt (key, msg, size,
                      ENCRYPT, iv);
size2 = strlen(msg) + 1 ;
printf("size2 = %d\n", size2);
fedprint(msg, 30);
#if 0
Base64Encode(out, msg, 0);


#if 0
printf("DES\n");
fedprint(msg,size);
s_des_encrypt(key,iv,msg,&size);

printf("Enc\n");
fedprint(msg,size);
Base64Encode(out, msg, 0);
#endif

printf("Out = %s\n", out);

Base64Decode(msg, out, 0);
fedprint(msg,size2);
size2 = strlen(msg);
printf("size2 = %d\n", size2);
//printf("Out = %s\n", out);

//des_setparity(key);
//Base64Decode(out, msg, 0);
//size = 32;
//pad(out, &size);
//printf("Out = %s, size = %d\n", out, size);
printf("size = %d\n", size);
#endif
pad(msg,&size2);

printf(" size2 = %d\n", size2);

cbc_crypt (key, msg, 9, \
                      DES_DECRYPT, iv);
printf("%s\n",msg);
//s_des_decrypt(key,iv,out,size);

//printf("Dec\n");
//fedprint(msg,size);
//printf("%s\n",msg);
//printf("msg = %s\n", out);

//Base64Decode(msg, out, 0);
//printf("Out = %s\n", out);
#if 0
printf("T DES\n");
fedprint(msg,size);
t_des_encrypt(key,key2,iv,msg,&size);

fedprint(msg,size);
t_des_decrypt(key,key2,iv,msg,size);

fedprint(msg,size);
printf("%s\n",msg);
#endif
return ;

}

#if 0
main(char* argv, int argc)
{

 unsigned char key[8] = "abcdefgh";
 unsigned char key2[8] = "12345678";
 des_setparity(key);
 des_setparity(key2);

 unsigned char msg[100] = "hello world";
 unsigned char iv[BLOCK_SIZE] = "awarfhss";

 
 int size = strlen(msg)+1;

/*  if((size % BLOCK_SIZE) != 0){
	char * newmsg;
	int newsize = ((size/BLOCK_SIZE)+1)*BLOCK_SIZE;
	newmsg = malloc(newsize);
	memset(newmsg,'\0',newsize);
	strcpy(newmsg,msg);
	msg = newmsg;
	size = newsize;
  }*/


pad(msg,&size);
printf("%s,%d\n",msg,size);

printf("DES\n");
fedprint(msg,size);
s_des_encrypt(key,iv,msg,&size);

printf("Enc\n");
fedprint(msg,size);
s_des_decrypt(key,iv,msg,size);

printf("Dec\n");
fedprint(msg,size);
printf("%s\n",msg);

printf("T DES\n");
fedprint(msg,size);
t_des_encrypt(key,key2,iv,msg,&size);

fedprint(msg,size);
t_des_decrypt(key,key2,iv,msg,size);

fedprint(msg,size);
printf("%s\n",msg);

return 0;
}
#endif

void cbc( unsigned char * msg,int blocklen,int blocknum, unsigned char * iv)
{
	int i;

	//printf("blocklen = %d, blocknum = %d\n", blocklen, blocknum);
	if(blocknum==0){
		for(i=0; i<blocklen; i++){
			msg[i]  = msg[i] ^ iv[i];
		}
	}else{
		for(i=blocknum;i<(blocknum+blocklen);i++){
			msg[i] = msg[i-blocklen] ^ msg[i];
		}
	}
}

void fedprint( unsigned char * msg, int len){
	int i;
	printf("size: %d\n",len);
	for(i=0;i<len; i++){
		printf("%03d ",msg[i]);
	}
	printf("\n");
}

void s_des_encrypt( unsigned char * key,  unsigned char * iv,  unsigned char * msg, int * size)
{
	int i;
	int blocksize=BLOCK_SIZE;
	int rv;

//	printf("here, char meg = %s, size = %d\n", msg, *size);

	for(i=0; i<*size; i+=blocksize){
		cbc(msg,blocksize,i,iv);
		rv = ecb_crypt(key,msg+i,blocksize,DES_ENCRYPT);
	}
}

void t_des_encrypt( unsigned char * key,  unsigned char * key2,  unsigned char * iv,  unsigned char * msg, int * size){
	int i;
	int blocksize=BLOCK_SIZE;
	int rv;
	for(i=0; i<*size;i+=blocksize){
		cbc(msg,blocksize,i,iv);
		ecb_crypt(key,msg+i,blocksize,DES_ENCRYPT);
		ecb_crypt(key2,msg+i,blocksize,DES_DECRYPT);
		ecb_crypt(key,msg+i,blocksize,DES_ENCRYPT);
	}
}

void s_des_decrypt( unsigned char * key,  unsigned char * iv,  unsigned char * msg, int size){
	int i;
	int blocksize=BLOCK_SIZE;
	for(i=size; i>=0;i-=blocksize){
		ecb_crypt(key,msg+i,blocksize,DES_DECRYPT);
		cbc(msg,blocksize,i,iv);
	}		
}

void t_des_decrypt( unsigned char * key, unsigned char * key2,  unsigned char * iv,  unsigned char * msg, int size){
	int i;
	int blocksize=BLOCK_SIZE;
	for(i=size; i>=0;i-=blocksize){
		ecb_crypt(key,msg+i,blocksize,DES_DECRYPT);
		ecb_crypt(key2,msg+i,blocksize,DES_ENCRYPT);
		ecb_crypt(key,msg+i,blocksize,DES_DECRYPT);
		cbc(msg,blocksize,i,iv);
	}		
}

void pad1(char * msg, int * size)
{

  if((*size % BLOCK_SIZE) != 0){
    do {
       msg[(*size)++] = '\x0';
        //msg[(*size)++] = '-';

    } while ((*size) % 8 != 0);
}



}

void pad(char * msg, int * size)
{
#if 0
  if((*size % BLOCK_SIZE) != 0){
	char * newmsg;
	int newsize = ((*size/BLOCK_SIZE)+1)*BLOCK_SIZE;
	newmsg = malloc(newsize);
	memset(newmsg,'\0',newsize);
	strcpy(newmsg,msg);
	msg = newmsg;
	*size = newsize;
  }
#endif
if((*size % BLOCK_SIZE) != 0){
int a=8-(*size % BLOCK_SIZE);    
do {
       msg[(*size)++] = a;
        //msg[(*size)++] = '-';

    } while ((*size) % 8 != 0);
}
else
{
    do {
        msg[(*size)++] = '\x8';
        //msg[(*size)++] = '-';
    } while ((*size) % 8 != 0);



}
#if 0
  if((*size % BLOCK_SIZE) != 0){
	char * newmsg;
	int newsize = ((*size/BLOCK_SIZE)+1)*BLOCK_SIZE;
	*size = newsize;


  }
#endif

}


char * urlencode(char const *s, int len, int *new_length)
{
    unsigned char const *from, *end;
	char  *start, *to;
	char c;
    from = s;
    end = s + len;
    start = to = (unsigned char *) malloc(3 * len + 1);

    unsigned char hexchars[] = "0123456789ABCDEF";

    while (from < end) {
        c = *from++;

        if (c == ' ') {
            *to++ = '+';
        } else if ((c < '0' && c != '-' && c != '.')
                   ||(c < 'A' && c > '9')
                   ||(c > 'Z' && c < 'a' && c != '_')
                   ||(c > 'z')) {
            to[0] = '%';
            to[1] = hexchars[c >> 4];
            to[2] = hexchars[c & 15];
            to += 3;
        } else {
            *to++ = c;
        }
    }
    *to = 0;
    if (new_length) {
        *new_length = to - start;
    }
    return (char *) start;

}

