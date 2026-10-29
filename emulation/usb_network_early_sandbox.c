/* Emulator-only startup timing experiment. No UP setters or firmware writes.
 * Source NAND is a host-verified disposable copy with Web_active already1.
 * Native hardware-flag cache and its derived config table are the only updates.
 * Read-only menu queries diagnose whether presentation is separately gated.
 */
typedef unsigned int u32;
typedef void FILE;
extern FILE *fopen(const char *,const char *);
extern int fprintf(FILE *,const char *,...);
extern int fflush(FILE *);
extern int fclose(FILE *);
extern int mkdir(const char *,int);
extern int taskDelay(int);
extern int sysClkRateGet(void);
#include "usb_network_api_checks.h"
typedef struct {u32 words[32];} Object;
static u32 hash(const void *,u32);
static int pointer(void *);
static void objects(FILE *,const char *);
static void scalar(FILE *,void *,const char *,const char *);
#ifdef SMEG_EARLY_ASYNC
static int early_worker(void);
extern int taskSpawn(char *,int,int,int,int (*)(void),int,int,int,int,int,int,int,int,int,int);
#endif
#ifdef SMEG_EARLY_BOOTSTRAP
static int native_app_start(void);
#endif

/* Native ENTRY:YES starts at text offset0. */
#ifdef SMEG_EARLY_ASYNC
int smeg_usb_early_network(void)
{
    int task=taskSpawn("tSmegNetProbe",
#ifdef SMEG_EARLY_BOOTSTRAP
                       60,
#else
                       120,
#endif
                       0,32768,early_worker,0,0,0,0,0,0,0,0,0,0);
    return task<0?-100:0;
}
static int early_worker(void)
#else
int smeg_usb_early_network(void)
#endif
{
    int (*get)(const char *)=(int (*)(const char *))0x112bbf0u;
    int (*update)(void *,void *,int)=(int (*)(void *,void *,int))0x112a994u;
    int (*publish)(void *)=(int (*)(void *))0x112abe4u;
    void (*ctor)(void *,const char *)=(void (*)(void *,const char *))0x11334e8u;
    void (*dtor)(void *)=(void (*)(void *))0x1958d74u;
    unsigned attempt,i,changes=0,wait_limit,active_limit;
    int matched=0,rate=sysClkRateGet(),ticks,rc=-1;
    void *config;Object key;
    FILE *log;
    if(rate<1||rate>10000)return -9;
    ticks=rate/20;if(ticks<1)ticks=1;
#ifdef SMEG_EARLY_BOOTSTRAP
    ticks=1;
#endif
    wait_limit=(60u*(unsigned)rate+(unsigned)ticks-1)/(unsigned)ticks;
    active_limit=(30u*(unsigned)rate+(unsigned)ticks-1)/(unsigned)ticks;
    if(mkdir("/bd0/SMEG_EARLY_NET",0777)!=0)return -1;
    log=fopen("/bd0/SMEG_EARLY_NET/report.txt","wb");if(!log)return -2;
    fprintf(log,"QEMU ONLY startup cache experiment; no stored preference setters\n");
    fprintf(log,"TIMING rate=%d ticks=%d wait_polls=%u active_polls=%u\n",rate,ticks,wait_limit,active_limit);
#ifdef SMEG_EARLY_ASYNC
    fprintf(log,"EXECUTION bounded background worker; native entry returned to boot\n");
#endif
    fflush(log);
    for(attempt=0;attempt<wait_limit;++attempt){
        matched=1;
        for(i=0;i<sizeof(network_checks)/sizeof(network_checks[0]);++i)
            if(hash((void *)network_checks[i].address,network_checks[i].length)!=network_checks[i].hash){matched=0;break;}
        if(matched)break;
        taskDelay(ticks);
    }
    if(!matched){fprintf(log,"ABORT base API bytes not ready\n");fclose(log);return -3;}
    fprintf(log,"BASE_APIS_READY poll=%u\n",attempt);objects(log,"API_READY");
#ifdef SMEG_EARLY_BOOTSTRAP
    {
        int app_task;
        if(*(u32 *)0x2ef8b9cu||*(u32 *)0x2fbe7e0u||*(u32 *)0x5a86e30u||*(u32 *)0x2fba93cu){
            fprintf(log,"ABORT application/Qt initialization already present; no duplicate start\n");fclose(log);return -7;
        }
        /* Native entry performs its original constructors/package sequence.
         * VX_FP_TASK=8: give its native Qt bootstrap a floating-point context. */
        app_task=taskSpawn("tSmegNativeMain",121,8,196608,native_app_start,0,0,0,0,0,0,0,0,0,0);
        fprintf(log,"BOOTSTRAP native InitializeMetaAudioBt task=%08x\n",(u32)app_task);fflush(log);
        if(app_task<0){fclose(log);return -8;}
    }
#endif
    for(attempt=0;attempt<wait_limit;++attempt){
        config=*(void **)0x2ef8b9cu;
        if(pointer(config)&&get("HW_FLAG_SMEG_INT_E")==1)break;
        taskDelay(ticks);
    }
    if(attempt==wait_limit){
        fprintf(log,"ABORT existing INT_E flag never became1 config=%08x value=%d\n",(u32)config,pointer(config)?get("HW_FLAG_SMEG_INT_E"):-99);
        objects(log,"CONFIG_TIMEOUT");fclose(log);return -4;
    }
    fprintf(log,"INT_E_READY poll=%u config=%08x\n",attempt,(u32)config);objects(log,"BEFORE_OVERRIDE");
    ctor(&key,"HW_FLAG_SMEG_INT_E");
    for(i=0;i<active_limit;++i){
        if(*(void **)0x2ef8b9cu!=config){fprintf(log,"ABORT config instance changed; no stale pointer writes\n");dtor(&key);fclose(log);return -5;}
        if(get("HW_FLAG_SMEG_INT_E")==1){
            rc=update(config,&key,0);
            fprintf(log,"CACHE_OVERRIDE iteration=%u status=%d readback=%d\n",i,rc,get("HW_FLAG_SMEG_INT_E"));fflush(log);
            if(rc!=0||get("HW_FLAG_SMEG_INT_E")!=0){dtor(&key);fclose(log);return -6;}
            ++changes;rc=publish(config);
            fprintf(log,"DERIVED_CONFIG refresh_status=%d\n",rc);fflush(log);
        }
        taskDelay(ticks);
    }
    dtor(&key);objects(log,"AFTER_STARTUP_WINDOW");
    {
        void *desktop=*(void **)0x2f61b94u;
        if(pointer(desktop)){
            void *db=*(void **)((unsigned char *)desktop+0xd4u);
            if(pointer(db)){
                scalar(log,db,"menu8_count","SELECT count(*) FROM current_menu WHERE application_ID=8;");
                scalar(log,db,"menu8_present","SELECT count(*) FROM current_menu WHERE application_ID=8 AND is_present=1;");
                scalar(log,db,"root8000_flags","SELECT max(10*is_present+is_active) FROM current_menu WHERE item_ID=8000;");
            }else fprintf(log,"MENU_READ database unavailable\n");
        }else fprintf(log,"MENU_READ desktop not initialized\n");
    }
    fprintf(log,"FINISHED EARLY_NETWORK changes=%u current_INT_E=%d\n",changes,get("HW_FLAG_SMEG_INT_E"));fflush(log);fclose(log);return 0;
}

static u32 hash(const void *p,u32 n)
{const unsigned char *b=p;u32 h=2166136261u;while(n--)h=(h^*b++)*16777619u;return h;}
static int pointer(void *p)
{u32 a=(u32)p;return a>=0x3000000u&&a<0x1f000000u&&(a&3)==0;}
#ifdef SMEG_EARLY_BOOTSTRAP
static int native_app_start(void)
{return ((int (*)(void))0x1000000u)();}
#endif
static void objects(FILE *log,const char *stage)
{
    void *bt=*(void **)0x2fbe7e0u,*www=*(void **)0x5a86e30u;
    fprintf(log,"OBJECTS stage=%s BT=%08x WWW=%08x",stage,(u32)bt,(u32)www);
    if(pointer(bt))fprintf(log," BT_cached_INT_E=%u",*((unsigned char *)bt+0x51006u));
    if(pointer(www))fprintf(log," web_available=%u portal_available=%u",*((unsigned char *)www+0x51391u),*((unsigned char *)www+0x51390u));
    fprintf(log,"\n");fflush(log);
}
static void scalar(FILE *log,void *db,const char *name,const char *sql)
{
    void (*str_ctor)(void *,const char *,int,int,int)=(void (*)(void *,const char *,int,int,int))0x1021848u;
    void (*str_dtor)(void *)=(void (*)(void *))0x1022924u;
    void (*req_ctor)(void *,const void *)=(void (*)(void *,const void *))0x10f21c0u;
    /* D1 destroys a caller-owned object. D0 also frees its storage. */
    void (*req_dtor)(void *)=(void (*)(void *))0x10f1dccu;
    int (*execute)(void *,void *)=(int (*)(void *,void *))0x10f557cu;
    int (*has)(const void *)=(int (*)(const void *))0x10f1ce0u;
    int (*value)(const void *)=(int (*)(const void *))0x10f1cf0u;
    Object str,request;int rc;
    str_ctor(&str,sql,-1,0,1);req_ctor(&request,&str);rc=execute(db,&request);
    fprintf(log,"MENU_READ name=%s status=%d has_response=%d value=%d\n",name,rc,has(&request),value(&request));fflush(log);
    req_dtor(&request);str_dtor(&str);
}
