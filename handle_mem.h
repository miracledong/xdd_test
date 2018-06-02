#ifndef HANDLE_MEM_H
#define HANDLE_MEN_H

#define memfree(p) do {if (p != NULL) {free(p);p = NULL;}}while(0) 
#define COPY_STRING(dst, src, src_len) do{memcpy((dst), (src), (src_len)); dst[(src_len)]='\0';}while(0);

char *memstr(char *buf, int len, char *substr);

#endif
