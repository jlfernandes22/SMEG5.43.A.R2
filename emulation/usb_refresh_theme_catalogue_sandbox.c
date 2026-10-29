/* QEMU-only theme catalogue retry reset after an original-database export.
 * This changes only upgrade.HarmoniesChecked to zero through native UP APIs.
 */
#ifndef SMEG_BACKUP_INCLUDED_EXTERNALLY
#define SMEG_EMULATOR_ONLY_SET_WEB 1
#define smeg_emulator_set_web smeg_refresh_theme_catalogue
#include "usb_backup_readonly.c"
#undef smeg_emulator_set_web
#undef SMEG_EMULATOR_ONLY_SET_WEB
#endif
#ifndef SMEG_CATALOGUE_MARKER_ONLY
typedef struct {unsigned words[32];} NativeObject;
#include "usb_warmlight_api_fingerprints.h"
#endif
#include "theme_catalogue_contract.h"

static unsigned catalogue_hash(const void *p,unsigned n)
{const unsigned char*b=p;unsigned h=2166136261u;while(n--)h=(h^*b++)*16777619u;return h;}

#ifdef SMEG_CATALOGUE_MARKER_ONLY
static int smeg_check_theme_cache_marker(void)
{
    unsigned char data[64];unsigned i;size_t n;FILE*f;int status;
    for(i=0;i<2;++i)if(catalogue_hash((const void*)catalogue_owner[i].address,64)!=catalogue_owner[i].hash)return -120;
    f=fopen("/SYSTEM_TMP_DATA/HarmoniesChecked.tst","rb");if(!f)return 0;
    n=fread(data,1,sizeof(data),f);status=ferror(f);if(fclose(f))status=1;
    if(status||n<7||n>=sizeof(data)||data[0]!='V'||data[1]!='A'||data[2]!='L'||data[3]!='U'||data[4]!='E'||data[5]!=':')return -122;
    for(i=6;i<n;++i)if(!((data[i]>='0'&&data[i]<='9')||data[i]=='\r'||data[i]=='\n'||data[i]==' '||!data[i]))return -123;
    return 0;
}
#endif

int smeg_refresh_theme_catalogue(void)
{
#ifdef SMEG_CATALOGUE_MARKER_ONLY
    static const char path[]="/SYSTEM_TMP_DATA/HarmoniesChecked.tst";
    unsigned char marker[64];unsigned i;size_t n;int status=-120;FILE *f,*log;
    extern int remove(const char *);
    log=fopen("/bd0/SMEG_BACKUP/theme-catalogue.txt","wb");if(!log)return status;
    for(i=0;i<2;++i)if(catalogue_hash((const void*)catalogue_owner[i].address,64)!=catalogue_owner[i].hash)goto marker_done;
    f=fopen(path,"rb");
    if(!f){fprintf(log,"NO_MARKER %s\n",path);status=0;goto marker_done;}
    n=fread(marker,1,sizeof(marker),f);status=ferror(f)?-121:0;if(fclose(f))status=-121;
    fprintf(log,"MARKER bytes=%u hex=",(unsigned)n);for(i=0;i<n;++i)fprintf(log,"%02x",marker[i]);fprintf(log,"\n");
    if(status||n<7||n>=sizeof(marker)||marker[0]!='V'||marker[1]!='A'||marker[2]!='L'||marker[3]!='U'||marker[4]!='E'||marker[5]!=':'){status=-122;goto marker_done;}
    for(i=6;i<n;++i)if(!((marker[i]>='0'&&marker[i]<='9')||marker[i]=='\r'||marker[i]=='\n'||marker[i]==' '||!marker[i])){status=-123;goto marker_done;}
    status=remove(path);fprintf(log,"REMOVE_THEME_CACHE_MARKER status=%d\n",status);
marker_done:
    fprintf(log,"CATALOGUE_RESULT status=%d\n",status);if(fflush(log))status=-124;if(fclose(log))status=-124;
    printf("SMEG_THEME_CATALOGUE_RESULT status=%d\n",status);return status;
#else
    static NativeObject section,name,old,request,verify;
    void *up;unsigned i;int before=-1,after=-1,status=-110,initialized=0;
    void*(*instance)(void)=(void*(*)(void))warm_api_checks[0].address;
    int(*get)(void*,const void*,const void*,void*)=(int(*)(void*,const void*,const void*,void*))warm_api_checks[1].address;
    int(*set)(void*,const void*)=(int(*)(void*,const void*))warm_api_checks[2].address;
    void(*ctor)(void*,const char*,int,int,int)=(void(*)(void*,const char*,int,int,int))warm_api_checks[3].address;
    void(*keys_ctor)(void*)=(void(*)(void*))warm_api_checks[4].address;
    int(*count)(const void*)=(int(*)(const void*))warm_api_checks[7].address;
    void(*keys_dtor)(void*)=(void(*)(void*))warm_api_checks[8].address;
    void(*str_dtor)(void*)=(void(*)(void*))warm_api_checks[9].address;
    int(*get_int)(const void*,const void*,const void*,int*,int)=(int(*)(const void*,const void*,const void*,int*,int))catalogue_api[0].address;
    int(*add_int)(void*,const void*,const void*,int,int)=(int(*)(void*,const void*,const void*,int,int))catalogue_api[1].address;
    FILE*log=fopen("/bd0/SMEG_BACKUP/theme-catalogue.txt","wb");if(!log)return status;
    for(i=0;i<10;++i)if(catalogue_hash((const void*)warm_api_checks[i].address,warm_api_checks[i].bytes)!=warm_api_checks[i].hash)goto done;
    for(i=0;i<2;++i)if(catalogue_hash((const void*)catalogue_api[i].address,64)!=catalogue_api[i].hash)goto done;
    up=instance();if(!up)goto done;
    ctor(&section,"upgrade",-1,0,1);ctor(&name,"HarmoniesChecked",-1,0,1);
    keys_ctor(&old);keys_ctor(&request);keys_ctor(&verify);initialized=1;
    if(get(up,&section,&name,&old)==-1||count(&old)!=1||get_int(&old,&section,&name,&before,0)||before<0||before>5){status=-111;goto done;}
    fprintf(log,"BEFORE upgrade.HarmoniesChecked.0=%d\n",before);
    if(before){
        if(!add_int(&request,&section,&name,0,0)||count(&request)!=1){status=-112;goto done;}
        if(set(up,&request)==-1){status=-113;goto done;}
    }
    if(get(up,&section,&name,&verify)==-1||get_int(&verify,&section,&name,&after,0)||after){status=-114;goto done;}
    fprintf(log,"AFTER upgrade.HarmoniesChecked.0=%d\n",after);status=0;
done:
    if(initialized){keys_dtor(&verify);keys_dtor(&request);keys_dtor(&old);str_dtor(&name);str_dtor(&section);}
    fprintf(log,"CATALOGUE_RESULT status=%d\n",status);
    if(fflush(log))status=-115;if(fclose(log))status=-115;
    printf("SMEG_THEME_CATALOGUE_RESULT status=%d\n",status);return status;
#endif
}
