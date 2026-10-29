/* Disposable-emulator USB experiment. No application text or firmware writes.
 * Stages1..3 modify existing RAM caches. Stage4 also refreshes the generated
 * config_system database. That DB is marked Persistent in the factory manager;
 * do not assume its durability before auditing and cold-boot verification.
 * Fixed AUDIO_BT_256 APIs, object fields and opcodes are fingerprint guarded.
 * Optional Web_active request is the sole intended persistent parameter change.
 */
#define SMEG_EMULATOR_ONLY_NETWORK_CACHE 1
#ifdef SMEG_NETWORK_ENABLE_WEB
#include "usb_set_web_sandbox.c"
#else
#include "usb_backup_readonly.c"
#endif
#include "usb_network_api_checks.h"
#ifndef SMEG_NETWORK_KEEP_AGENDA
#define SMEG_NETWORK_KEEP_AGENDA 0
#endif
typedef struct {u32 words[32];} StdString;
static u32 network_hash(const void *p,u32 count)
{const unsigned char *s=p;u32 h=2166136261u;while(count--)h=(h^*s++)*16777619u;return h;}
static int network_pointer(void *p)
{u32 a=(u32)p;return a>=0x03000000u&&a<0x1f000000u&&(a&3)==0;}

int smeg_emulator_network_cache(void)
{
    const char *key="HW_FLAG_SMEG_INT_E";
    void *(*instance)(void)=(void *(*)(void))0x0112a904u;
    int (*get)(const char *)=(int (*)(const char *))0x0112bbf0u;
    int (*update)(void *,void *,int)=(int (*)(void *,void *,int))0x0112a994u;
    int (*publish_tmp)(void *)=(int (*)(void *))0x0112abe4u;
    void (*construct)(void *,const char *)=(void (*)(void *,const char *))0x011334e8u;
    void (*destroy)(void *)=(void (*)(void *))0x01958d74u;
    void *(*bt_instance)(void)=(void *(*)(void))0x027bde48u;
    int (*bt_is_int_e)(void *)=(int (*)(void *))0x027b2b10u;
    void *(*agenda_instance)(void)=(void *(*)(void))0x0182d230u;
    void *config,*bt=0,*agenda=0;
    volatile unsigned char *bt_flag=0,*agenda_flag=0;
    int before,after,status=-1,changed=0,bt_changed=0,agenda_changed=0;
    unsigned i,bt_before=0,agenda_before=0;
    StdString name;
    FILE *log=fopen("/bd0/SMEG_BACKUP/network.txt","wb");if(!log)return -30;
    fprintf(log,"QEMU ONLY: native configuration RAM cache stage=%d\n",SMEG_NETWORK_STAGE);fflush(log);
    for(i=0;i<sizeof(network_checks)/sizeof(network_checks[0]);++i)
        if(network_hash((void *)network_checks[i].address,network_checks[i].length)!=network_checks[i].hash){
            fprintf(log,"ABORT API fingerprint %08x\n",network_checks[i].address);fclose(log);return -31;
        }
    config=instance();before=get(key);
    fprintf(log,"CONFIG BEFORE key=%s value=%d instance=%08x\n",key,before,(u32)config);fflush(log);
    if(!network_pointer(config)||before!=1){fprintf(log,"ABORT expected existing INT_E flag=1\n");fclose(log);return -32;}
    if(SMEG_NETWORK_STAGE>=2){
        bt=bt_instance();if(!network_pointer(bt)){fclose(log);return -33;}
        bt_flag=(volatile unsigned char *)bt+0x51006u;bt_before=*bt_flag;
        fprintf(log,"BLUETOOTH BEFORE instance=%08x byte=%u getter=%d\n",(u32)bt,bt_before,bt_is_int_e(bt));fflush(log);
        if(bt_before!=1||bt_is_int_e(bt)!=1){fclose(log);return -34;}
    }
    if(SMEG_NETWORK_STAGE>=3&&!SMEG_NETWORK_KEEP_AGENDA){
        agenda=agenda_instance();if(!network_pointer(agenda)){fclose(log);return -35;}
        agenda_flag=(volatile unsigned char *)agenda+0xbau;agenda_before=*agenda_flag;
        fprintf(log,"AGENDA BEFORE instance=%08x force_no_dun=%u\n",(u32)agenda,agenda_before);fflush(log);
        if(agenda_before!=1){fclose(log);return -36;}
    }
    construct(&name,key);
    status=update(config,&name,0);after=get(key);changed=after==0;
    fprintf(log,"CONFIG AFTER status=%d value=%d\n",status,after);fflush(log);
    if(status!=0||after!=0)goto rollback;
    if(bt_flag){*bt_flag=0;bt_changed=1;fprintf(log,"BLUETOOTH AFTER byte=%u getter=%d\n",*bt_flag,bt_is_int_e(bt));fflush(log);if(bt_is_int_e(bt)!=0)goto rollback;}
    if(agenda_flag){*agenda_flag=0;agenda_changed=1;fprintf(log,"AGENDA AFTER force_no_dun=%u\n",*agenda_flag);fflush(log);if(*agenda_flag!=0)goto rollback;}
    if(SMEG_NETWORK_STAGE>=4){
        fprintf(log,"PUBLISH derived config_system through native CreateTmpDataBase; no SaveSWOption\n");fflush(log);
        status=publish_tmp(config);
        fprintf(log,"PUBLISH status=%d config_value=%d\n",status,get(key));fflush(log);
        if(status!=0||get(key)!=0)goto rollback;
    }
    fprintf(log,"FINISHED NETWORK_CACHE stage=%d generated_config_refresh=%d firmware_writes=0\n",SMEG_NETWORK_STAGE,SMEG_NETWORK_STAGE>=4);
    destroy(&name);fflush(log);fclose(log);return 0;
rollback:
    if(agenda_changed)*agenda_flag=agenda_before;
    if(bt_changed)*bt_flag=bt_before;
    if(changed)update(config,&name,before);
    if(SMEG_NETWORK_STAGE>=4)publish_tmp(config);
    fprintf(log,"FAILED: RAM changes rolled back; config=%d\n",get(key));
    destroy(&name);fflush(log);fclose(log);return -37;
}

int smeg_emulator_network_finish(void)
{
    void *(*www_instance)(void)=(void *(*)(void))0x04c9b564u;
    int (*query)(void *,void *,void *)=(int (*)(void *,void *,void *))0x0278a95cu;
    int (*available)(void *)=(int (*)(void *))0x04c86cecu;
    void (*register_menu)(void *)=(void (*)(void *))0x04c90b10u;
    void *(*get_desktop_client)(void *)=(void *(*)(void *))0x04c863acu;
    int (*init_presence)(void *,const short *)=(int (*)(void *,const short *))0x0260480cu;
    void *www,*client;unsigned char *web,*portal;int status;
    FILE *log=fopen("/bd0/SMEG_BACKUP/network.txt","ab");if(!log)return -40;
    fprintf(log,"POST configuration notification complete; agenda_preserved=%d\n",SMEG_NETWORK_KEEP_AGENDA);fflush(log);
    if(SMEG_NETWORK_STAGE<5){fprintf(log,"FINISHED NETWORK_PROBE stage=%d\n",SMEG_NETWORK_STAGE);fclose(log);return 0;}
    www=www_instance();if(!network_pointer(www)){fclose(log);return -41;}
    client=*(void **)((unsigned char *)www+0x5111cu);
    if(!network_pointer(client)){fclose(log);return -42;}
    web=(unsigned char *)www+0x51391u;portal=(unsigned char *)www+0x51390u;
    fprintf(log,"BROWSER BEFORE object=%08x client=%08x web=%u portal=%u\n",(u32)www,(u32)client,*web,*portal);fflush(log);
    status=query(client,web,portal);
    fprintf(log,"BROWSER AFTER native_query_status=%d web=%u portal=%u native_getter=%d\n",status,*web,*portal,available(www));fflush(log);
    if(SMEG_NETWORK_STAGE>=6){
        void *root=*(void **)((unsigned char *)www+0x5114cu);
        void *manager=*(void **)((unsigned char *)www+0x510ecu);
        fprintf(log,"MENU root=%08x manager=%08x timer=%u\n",(u32)root,(u32)manager,*(u32 *)((unsigned char *)www+0x51128u));fflush(log);
        if(root==0&&network_pointer(manager)){
            fprintf(log,"MENU missing root: invoke native RegisterMenu once; existing roots never duplicated\n");fflush(log);
            register_menu(www);
            fprintf(log,"MENU after native registration root=%08x\n",*(u32 *)((unsigned char *)www+0x5114cu));fflush(log);
        }
    }
    if(SMEG_NETWORK_STAGE>=7){
        short application=8;void *desktop=get_desktop_client(www);int rc;
        if(!network_pointer(desktop)||!network_pointer(*(void **)((unsigned char *)desktop+0xc))){fprintf(log,"ABORT desktop presence proxy missing\n");fclose(log);return -44;}
        rc=init_presence(desktop,&application);
        fprintf(log,"MENU native InitPresenceApplication app=%d status=%d\n",application,rc);fflush(log);
        if(rc!=0){fclose(log);return -45;}
    }
    fprintf(log,"FINISHED NETWORK_PROBE stage=%d native_web_available=%d\n",SMEG_NETWORK_STAGE,available(www));
    fclose(log);return status==0?0:-43;
}
