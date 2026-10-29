#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { char path[160]; unsigned char data[65536]; size_t size; } MockNode;
typedef struct { MockNode *node; size_t position; int open, error; } MockFile;
static MockNode nodes[24]; static unsigned node_count;
static MockFile handles[24];
static int erased, bad_overlap, writes[8], write_count, reads[8], read_count;
static int publication, ui_failure_seen, case_id;
static char events[256]; static unsigned event_count;
static unsigned char original_pre[2][168], final_pre[2][168], big_header[2][2048];
static unsigned char original_entry[2][216], final_entry[2][216];
static unsigned char original_payload[2][64], final_payload[2][64];
static int installed[2];
static unsigned fnv(const void *p,size_t n){const unsigned char *b=p;unsigned h=2166136261u;while(n--)h=(h^*b++)*16777619u;return h;}
static unsigned crc32_mock(const void *p,size_t n){const unsigned char*b=p;unsigned crc=~0u;while(n--){crc^=*b++;for(unsigned i=0;i<8;i++)crc=(crc>>1)^((crc&1)?0xedb88320u:0);}return ~crc;}
static void event(char c){assert(event_count+1<sizeof(events));events[event_count++]=c;events[event_count]=0;}
static MockNode *node(const char*path,int create){for(unsigned i=0;i<node_count;i++)if(!strcmp(path,nodes[i].path))return &nodes[i];if(!create)return NULL;assert(node_count<24);MockNode*n=&nodes[node_count++];snprintf(n->path,sizeof(n->path),"%s",path);return n;}
static int is_source(const char*path){return strstr(path,"/THEME_TEST/")!=NULL || strstr(path,"original-bank")!=NULL;}
static MockFile *test_fopen(const char*path,const char*mode){
 if(case_id==20&&mode[0]=='r'&&strstr(path,"bank2.bin.inf"))return NULL;
 if(erased&&((case_id==10&&strstr(path,"theme-install.txt"))||(case_id==16&&strstr(path,"theme-progress.txt"))))return NULL;
 for(unsigned i=0;i<24;i++)if(handles[i].open && is_source(handles[i].node->path) && !is_source(path))bad_overlap=1;
 MockNode*n=node(path,mode[0]!='r');if(!n)return NULL;
 if(mode[0]=='w')n->size=0;
 for(unsigned i=0;i<24;i++)if(!handles[i].open){MockFile*f=&handles[i];*f=(MockFile){.node=n,.position=mode[0]=='a'?n->size:0,.open=1};return f;}
 assert(0);return NULL;
}
static size_t test_fread(void*p,size_t size,size_t count,MockFile*f){assert(f&&f->open);size_t n=size*count;if(n>f->node->size-f->position)n=f->node->size-f->position;memcpy(p,f->node->data+f->position,n);f->position+=n;return size?n/size:0;}
static size_t test_fwrite(const void*p,size_t size,size_t count,MockFile*f){assert(f&&f->open);size_t n=size*count;assert(f->position+n<=sizeof(f->node->data));memcpy(f->node->data+f->position,p,n);f->position+=n;if(f->position>f->node->size)f->node->size=f->position;return count;}
static int test_fprintf(MockFile*f,const char*fmt,...){assert(f&&f->open);char text[4096];va_list ap;va_start(ap,fmt);int n=vsnprintf(text,sizeof(text),fmt,ap);va_end(ap);assert(n>=0&&(unsigned)n<sizeof(text));test_fwrite(text,1,(size_t)n,f);return n;}
static int test_ferror(MockFile*f){assert(f&&f->open);return f->error||(erased&&case_id==15&&strstr(f->node->path,"theme-install.txt"));}
static int test_fflush(MockFile*f){assert(f&&f->open);return erased&&(case_id==11||case_id==17)&&strstr(f->node->path,"theme-install.txt")?-1:0;}
static int test_fclose(MockFile*f){assert(f&&f->open);int fail=erased&&case_id==12&&strstr(f->node->path,"theme-install.txt");f->open=0;return fail?-1:0;}
static int test_printf(const char*fmt,...){(void)fmt;return 0;}
int errnoGet(void){return 5;} int taskDelay(int n){(void)n;return 0;}
static int test_progress(const char*message){if(erased&&(case_id==9||(case_id==19&&!strcmp(message,"Copy previews")))){ui_failure_seen=1;return -1;}return 0;}
static int mock_read_pre(int bank,void*out){assert(bank==1||bank==2);if(erased){assert(read_count<8);reads[read_count++]=bank;event(bank==2?'r':'s');if((case_id==4&&bank==2)||(case_id==5&&bank==1)||!installed[bank-1])return -104;}memcpy(out,erased?final_pre[bank-1]:original_pre[bank-1],168);return 0;}
static int mock_read_big(int bank,void*out){if(erased&&case_id==8&&bank==2)return -108;memcpy(out,big_header[bank-1],2048);return 0;}
static int mock_read_entry(int bank,int number,void*out){assert(number==1);memcpy(out,erased?final_entry[bank-1]:original_entry[bank-1],216);return 0;}
static int mock_read_payload(int bank,const void*entry,void*out){(void)entry;if(erased&&case_id==7&&bank==1)return -107;memcpy(out,erased?final_payload[bank-1]:original_payload[bank-1],64);if(erased&&case_id==6&&bank==2)((unsigned char*)out)[0]^=1;return 0;}
static int mock_write_bank(int bank,const char*path){assert(erased&&bank>=1&&bank<=2);assert(strstr(path,bank==1?"bank1.bin":"bank2.bin"));for(unsigned i=0;i<24;i++)if(handles[i].open)bad_overlap=1;assert(write_count<8);writes[write_count++]=bank;event(bank==2?'2':'1');if((case_id==2&&bank==2)||(case_id==3&&bank==1)||(case_id==17&&bank==2)||case_id==18)return -200-bank;installed[bank-1]=1;return 0;}
static int mock_erase(void){assert(!erased);erased=1;event('E');return case_id==1||case_id==17?-205:0;}
static int dummy_api(void){return 0;}
#define FILE MockFile
#define fopen test_fopen
#define fread test_fread
#define fwrite test_fwrite
#define fprintf test_fprintf
#define ferror test_ferror
#define fflush test_fflush
#define fclose test_fclose
#define printf test_printf
#define SMEG_NATIVE_THEME_PROGRESS 1
#define SMEG_COMPLETE_REGISTER_CATALOGUE 1
#define SMEG_COMPLETE_REFRESH_CATALOGUE 1
#include "usb_complete_themes_sandbox.c"
#undef printf
static void init(void){
 void *funcs[6]={(void*)mock_read_pre,(void*)mock_read_big,(void*)mock_read_entry,(void*)mock_write_bank,(void*)mock_erase,(void*)mock_read_payload};
 for(unsigned i=0;i<6;i++){resource_api[i].address=(uintptr_t)funcs[i];resource_api[i].bytes=64;resource_api[i].hash=fnv(funcs[i],64);}
 for(unsigned bank=0;bank<2;bank++){
  memset(original_pre[bank],0x11+(int)bank,168);memset(final_pre[bank],0x31+(int)bank,168);memset(big_header[bank],0x41+(int)bank,2048);
  memset(original_payload[bank],0x51+(int)bank,64);memset(final_payload[bank],0x61+(int)bank,64);
  memset(original_entry[bank],0x71+(int)bank,216);memset(final_entry[bank],0x81+(int)bank,216);
  ((unsigned*)original_entry[bank])[208/4]=64;((unsigned*)original_entry[bank])[212/4]=crc32_mock(original_payload[bank],64);
  ((unsigned*)final_entry[bank])[208/4]=64;((unsigned*)final_entry[bank])[212/4]=crc32_mock(final_payload[bank],64);
  memcpy(big_header[bank]+36,final_entry[bank],216);
  original_pre_hash[bank]=fnv(original_pre[bank],168);
  resource_files[bank].bank=bank+1;resource_files[bank].path=bank?"/bd0/THEME_TEST/bank2.bin":"/bd0/THEME_TEST/bank1.bin";
  MockNode*n=node(resource_files[bank].path,1);memset(n->data,0xa1+(int)bank,64);n->size=64;
  resource_files[bank].bytes=64;resource_files[bank].crc32=crc32_mock(n->data,n->size);resource_files[bank].pre_hash=fnv(final_pre[bank],168);resource_files[bank].big_hash=fnv(big_header[bank],36);resource_files[bank].count=1;resource_files[bank].entry_hash[0]=fnv(final_entry[bank],216);
  resource_inf_files[bank].path=bank?"/bd0/THEME_TEST/bank2.bin.inf":"/bd0/THEME_TEST/bank1.bin.inf";
  n=node(resource_inf_files[bank].path,1);memset(n->data,0xd1+(int)bank,16);n->size=16;
  resource_inf_files[bank].bytes=16;resource_inf_files[bank].crc32=crc32_mock(n->data,n->size);
 }
 for(unsigned i=0;i<10;i++){warm_api_checks[i].address=(uintptr_t)dummy_api;warm_api_checks[i].bytes=64;warm_api_checks[i].hash=fnv((void*)dummy_api,64);}
 for(unsigned i=0;i<2;i++){preview_fs_api[i].address=(uintptr_t)dummy_api;preview_fs_api[i].hash=fnv((void*)dummy_api,64);common_bsp[i]=preview_fs_api[i];}
 for(unsigned i=0;i<13;i++){common_api[i].address=(uintptr_t)dummy_api;common_api[i].hash=fnv((void*)dummy_api,64);}
 for(unsigned i=0;i<6;i++){MockNode*n=node(preview_paths[i],1);memset(n->data,0xb1+(int)i,16);n->size=16;theme_previews[i].source=preview_paths[i];theme_previews[i].bytes=16;theme_previews[i].hash=fnv(n->data,n->size);}
 if(case_id==13)node("/bd0/THEME_TEST/bank1.bin",0)->data[0]^=1;
 if(case_id==14)resource_api[0].hash^=1;
 if(case_id==21)node("/bd0/THEME_TEST/bank1.bin.inf",0)->data[0]^=1;
}
int main(int argc,char**argv){assert(argc==2);case_id=atoi(argv[1]);init();int status=smeg_complete_theme_install();
 printf("{\"case\":%d,\"status\":%d,\"events\":\"%s\",\"erased\":%d,\"writes\":[",case_id,status,events,erased);
 for(int i=0;i<write_count;i++)printf("%s%d",i?",":"",writes[i]);printf("],\"reads\":[");for(int i=0;i<read_count;i++)printf("%s%d",i?",":"",reads[i]);
 printf("],\"publication\":%d,\"ui_failure_seen\":%d,\"bad_overlap\":%d}\n",publication,ui_failure_seen,bad_overlap);return 0;}
