/* Native, bounded registration of six installed theme names and mappings.
 * Requires exact installed bank preheaders/directories, backs up original
 * databases through the entry wrapper, and refuses conflicting old values.
 */
#ifndef SMEG_BACKUP_INCLUDED_EXTERNALLY
#define SMEG_EMULATOR_ONLY_SET_WEB 1
#define smeg_emulator_set_web smeg_set_theme_catalogue
#include "usb_backup_readonly.c"
#undef smeg_emulator_set_web
#undef SMEG_EMULATOR_ONLY_SET_WEB
#endif
typedef struct{unsigned words[32];} CatalogueObject;
#include "theme_common_catalogue_contract.h"
extern int strcmp(const char*,const char*);
static unsigned common_catalogue_hash(const void*p,unsigned n)
{const unsigned char*b=p;unsigned h=2166136261u;while(n--)h=(h^*b++)*16777619u;return h;}

int smeg_set_theme_catalogue(void)
{
    static CatalogueObject section,name,value,target,request,verify,string;
    static unsigned char pre[168],entry[216];
    unsigned i,j,changed=0;int status=-130,initialized=0;void *up;
    void*(*instance)(void)=(void*(*)(void))common_api[0].address;
    int(*get)(void*,const void*,const void*,void*)=(int(*)(void*,const void*,const void*,void*))common_api[1].address;
    int(*set)(void*,const void*)=(int(*)(void*,const void*))common_api[2].address;
    void(*ctor)(void*,const char*,int,int,int)=(void(*)(void*,const char*,int,int,int))common_api[3].address;
    void(*kc)(void*)=(void(*)(void*))common_api[4].address;
    int(*gi)(const void*,const void*,const void*,int*,int)=(int(*)(const void*,const void*,const void*,int*,int))common_api[5].address;
    int(*ai)(void*,const void*,const void*,int,int)=(int(*)(void*,const void*,const void*,int,int))common_api[6].address;
    int(*gs)(const void*,const void*,const void*,void*,int)=(int(*)(const void*,const void*,const void*,void*,int))common_api[7].address;
    int(*as)(void*,const void*,const void*,const void*,int)=(int(*)(void*,const void*,const void*,const void*,int))common_api[8].address;
    int(*count)(const void*)=(int(*)(const void*))common_api[9].address;
    void(*kd)(void*)=(void(*)(void*))common_api[10].address;
    void(*sd)(void*)=(void(*)(void*))common_api[11].address;
    const char*(*text)(const void*,int,void*)=(const char*(*)(const void*,int,void*))common_api[12].address;
    int(*rp)(int,void*)=(int(*)(int,void*))common_bsp[0].address;
    int(*re)(int,int,void*)=(int(*)(int,int,void*))common_bsp[1].address;
    FILE*log=fopen("/bd0/SMEG_BACKUP/theme-catalogue.txt","wb");if(!log)return status;
    for(i=0;i<13;++i)if(common_catalogue_hash((const void*)common_api[i].address,64)!=common_api[i].hash)goto done;
    for(i=0;i<2;++i)if(common_catalogue_hash((const void*)common_bsp[i].address,64)!=common_bsp[i].hash)goto done;
    for(i=0;i<2;++i){
        if(rp(i+1,pre)||common_catalogue_hash(pre,168)!=catalogue_banks[i].pre_hash){status=-131;goto done;}
        for(j=0;j<4;++j)if(re(i+1,j+1,entry)||common_catalogue_hash(entry,216)!=catalogue_banks[i].entries[j]){status=-132;goto done;}
    }
    up=instance();if(!up)goto done;
    ctor(&section,"supervisor",-1,0,1);kc(&request);initialized=1;
    for(i=0;i<18;++i){
        const struct CommonRow*r=&common_rows[i];int old=-1,valid;
        ctor(&name,r->name,-1,0,1);kc(&value);
        valid=get(up,&section,&name,&value)!=-1&&count(&value)==1;
        if(valid&&r->string){
            const char *s;ctor(&string,"",-1,0,1);ctor(&target,r->string,-1,0,1);
            valid=gs(&value,&section,&name,&string,0)==0;s=valid?text(&string,0,0):0;
            valid=valid&&s&&(!*s||!strcmp(s,r->string));
            if(valid&&strcmp(s,r->string)){valid=as(&request,&section,&name,&target,0)!=0;++changed;}
            fprintf(log,"KEY supervisor.%s old=%s target=%s valid=%d\n",r->name,s?s:"<invalid>",r->string,valid);
            sd(&target);sd(&string);
        }else if(valid){
            valid=gi(&value,&section,&name,&old,0)==0&&(old==0||old==r->integer);
            if(valid&&old!=r->integer){valid=ai(&request,&section,&name,r->integer,0)!=0;++changed;}
            fprintf(log,"KEY supervisor.%s old=%d target=%d valid=%d\n",r->name,old,r->integer,valid);
        }
        kd(&value);sd(&name);
        if(!valid||count(&request)!=(int)changed){status=-133;goto done;}
    }
    if(changed&&set(up,&request)==-1){status=-134;goto done;}
    for(i=0;i<18;++i){
        const struct CommonRow*r=&common_rows[i];int got=-1,valid;
        ctor(&name,r->name,-1,0,1);kc(&verify);valid=get(up,&section,&name,&verify)!=-1&&count(&verify)==1;
        if(valid&&r->string){const char*s;ctor(&string,"",-1,0,1);valid=gs(&verify,&section,&name,&string,0)==0;s=valid?text(&string,0,0):0;valid=valid&&s&&!strcmp(s,r->string);sd(&string);}
        else if(valid)valid=gi(&verify,&section,&name,&got,0)==0&&got==r->integer;
        kd(&verify);sd(&name);if(!valid){status=-135;goto done;}
    }
    fprintf(log,"VERIFIED_NATIVE_COMMON_CATALOGUE keys=18 changed=%u\n",changed);status=0;
done:
    if(initialized){kd(&request);sd(&section);}
    fprintf(log,"CATALOGUE_RESULT status=%d\n",status);if(fflush(log))status=-136;if(fclose(log))status=-136;
    printf("SMEG_NATIVE_COMMON_CATALOGUE_RESULT status=%d\n",status);return status;
}
