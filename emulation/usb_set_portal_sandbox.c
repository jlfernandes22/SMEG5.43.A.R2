/* Emulator-only native one-key portal-location capability test, after backup.
 * No instruction writes, firmware replacement, remote URLs or vehicle actions.
 */
#define SMEG_EMULATOR_ONLY_SET_PORTAL 1
#include "usb_backup_readonly.c"
extern int strcmp(const char *,const char *);
typedef struct {unsigned int words[32];} NativeObject;
#include "usb_portal_api_fingerprints.h"
#ifdef SMEG_PORTAL_CONTENT_INSTALL
static int smeg_install_portal_content(void);
#endif
#ifdef SMEG_RESTORE_STOCK_PORTAL
#define EXPECTED_PORTAL "/bd0/SMEG_CAP/index.html"
#define TARGET_PORTAL "/SYSTEM/internet_default/portal/index.html"
#else
#define EXPECTED_PORTAL "/SYSTEM/internet_default/portal/index.html"
#ifndef TARGET_PORTAL
#define TARGET_PORTAL "/bd0/SMEG_CAP/index.html"
#endif
#endif
static unsigned int portal_hash(const void *p,unsigned int n)
{const unsigned char *b=p;unsigned int h=2166136261u;while(n--)h=(h^*b++)*16777619u;return h;}

int smeg_emulator_set_portal(void)
{
    NativeObject section,name,before,after,target,old,request,verify;
    unsigned int profile,i;int matched=0,status=-1;
    const void *fn[11];void *up;const char *original,*saved;
    void *(*instance)(void);
    int (*get)(void *,const void *,const void *,void *);
    int (*set)(void *,const void *);
    void (*ctor)(void *,const char *,int,int,int),(*dtor)(void *);
    void (*keys_ctor)(void *),(*keys_dtor)(void *);
    int (*get_string)(const void *,const void *,const void *,void *,int);
    int (*add_string)(void *,const void *,const void *,const void *,int);
    int (*count)(const void *);
    const char *(*buffer)(const void *,int,void *);
    FILE *log=fopen("/bd0/SMEG_BACKUP/change.txt","wb");if(!log)return -20;
    fprintf(log,"QEMU ONLY: native one-key portal path test after full backup\n");
    for(profile=0;profile<2;++profile){
        matched=1;
        for(i=0;i<11;++i){
            unsigned int a=profile?api_checks[i].audio_address:api_checks[i].nav_address;
            unsigned int h=profile?api_checks[i].audio_hash:api_checks[i].nav_hash;
            fn[i]=(const void *)a;
            if(portal_hash(fn[i],api_checks[i].bytes)!=h){matched=0;break;}
        }
        if(matched)break;
    }
    if(!matched){fprintf(log,"ABORT: exact native API fingerprints missing\n");fclose(log);return -21;}
    instance=(void *(*)(void))fn[0];get=(int (*)(void *,const void *,const void *,void *))fn[1];
    set=(int (*)(void *,const void *))fn[2];ctor=(void (*)(void *,const char *,int,int,int))fn[3];
    keys_ctor=(void (*)(void *))fn[4];get_string=(int (*)(const void *,const void *,const void *,void *,int))fn[5];
    add_string=(int (*)(void *,const void *,const void *,const void *,int))fn[6];count=(int (*)(const void *))fn[7];
    keys_dtor=(void (*)(void *))fn[8];dtor=(void (*)(void *))fn[9];buffer=(const char *(*)(const void *,int,void *))fn[10];
    up=instance();if(!up){fprintf(log,"ABORT: no UP instance\n");fclose(log);return -22;}
    ctor(&section,"internet",-1,0,1);ctor(&name,"URL_PSA_portal",-1,0,1);
    ctor(&before,"",-1,0,1);ctor(&after,"",-1,0,1);ctor(&target,TARGET_PORTAL,-1,0,1);
    keys_ctor(&old);keys_ctor(&request);keys_ctor(&verify);
    if(get(up,&section,&name,&old)==-1||count(&old)!=1||get_string(&old,&section,&name,&before,0)!=0){
        fprintf(log,"ABORT: existing string not readable\n");goto done;
    }
    original=buffer(&before,0,0);
    if(!original||strcmp(original,EXPECTED_PORTAL)){
        fprintf(log,"ABORT: expected prior portal location missing\n");goto done;
    }
    fprintf(log,"BEFORE internet.URL_PSA_portal=%s\n",original);
#ifdef SMEG_PORTAL_CONTENT_INSTALL
    if(smeg_install_portal_content()!=0){status=-26;goto done;}
#endif
    if(!add_string(&request,&section,&name,&target,0)||count(&request)!=1)goto done;
    status=set(up,&request);
    if(status==-1||get(up,&section,&name,&verify)==-1||get_string(&verify,&section,&name,&after,0)!=0){status=-23;goto done;}
    saved=buffer(&after,0,0);
    if(!saved||strcmp(saved,TARGET_PORTAL)){status=-24;goto done;}
    fprintf(log,"AFTER internet.URL_PSA_portal=%s\nFINISHED native portal target saved\n",saved);
done:
    fprintf(log,"STATUS=%d\n",status);keys_dtor(&verify);keys_dtor(&request);keys_dtor(&old);
    dtor(&target);dtor(&after);dtor(&before);dtor(&name);dtor(&section);fflush(log);fclose(log);return status;
}
