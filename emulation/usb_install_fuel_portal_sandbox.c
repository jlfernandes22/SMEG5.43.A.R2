/* Isolated experiment: install one new HTML file, then change one portal URL.
 * The stock portal, application binary and other preference keys are retained.
 */
#define SMEG_PORTAL_CONTENT_INSTALL 1
#define TARGET_PORTAL "/SYSTEM/internet_default/customfuel/index.html"
#include "usb_set_portal_sandbox.c"
#include "theme_preview_fs_contract.h"
#include "portal_content_contract.h"
extern void *opendir(const char *);
extern int closedir(void *);

static int portal_file_valid(const char *path)
{
    FILE *f=fopen(path,"rb");unsigned count=0,h=2166136261u;size_t n,i;int bad;
    if(!f)return 0;
    while((n=fread(buffer,1,sizeof(buffer),f))!=0){count+=n;for(i=0;i<n;++i)h=(h^buffer[i])*16777619u;}
    bad=ferror(f)||count!=PORTAL_CONTENT_BYTES||h!=PORTAL_CONTENT_HASH;
    if(fclose(f))bad=1;
    return !bad;
}

static int smeg_install_portal_content(void)
{
    unsigned i;int status=-1,prior=-1,changed=0;void *volume,*dir;FILE *in=0,*out=0,*existing;
    void *(*get)(const char *,void *)=(void *(*)(const char *,void *))preview_fs_api[0].address;
    int (*set)(const char *,int)=(int(*)(const char *,int))preview_fs_api[1].address;
    for(i=0;i<2;++i)if(portal_hash((const void *)preview_fs_api[i].address,64)!=preview_fs_api[i].hash)return -1;
    if(!portal_file_valid("/bd0/SMEG_CAP/index.html"))return -2;
    existing=fopen(TARGET_PORTAL,"rb");
    if(existing){fclose(existing);return portal_file_valid(TARGET_PORTAL)?0:-3;}
    volume=get("/SYSTEM",0);if(!volume)return -4;prior=(int)((const unsigned*)volume)[0x340/4];
    if(prior!=0&&prior!=1)return -5;
    if(prior){if(set("/SYSTEM",0))return -6;changed=1;}
    dir=opendir("/SYSTEM/internet_default/customfuel");
    if(dir)closedir(dir);else if(mkdir("/SYSTEM/internet_default/customfuel",0777))goto done;
    in=fopen("/bd0/SMEG_CAP/index.html","rb");if(!in)goto done;
    out=fopen(TARGET_PORTAL,"wb");if(!out)goto done;
    status=0;
    for(;;){size_t n=fread(buffer,1,sizeof(buffer),in);if(!n)break;if(fwrite(buffer,1,n,out)!=n){status=-7;break;}}
    if(ferror(in)||fflush(out))status=-8;
    if(fclose(in))status=-8;in=0;
    if(fclose(out))status=-8;out=0;
    if(!status&&!portal_file_valid(TARGET_PORTAL))status=-9;
done:
    if(in)fclose(in);if(out)fclose(out);
    if(changed&&(set("/SYSTEM",prior)||(int)((const unsigned*)volume)[0x340/4]!=prior))status=-10;
    printf("SMEG_FUEL_CONTENT_RESULT status=%d SYSTEM_RO=%u\n",status,((const unsigned*)volume)[0x340/4]);
    return status;
}
