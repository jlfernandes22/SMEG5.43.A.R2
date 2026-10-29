/* QEMU-ONLY prototype: native single-key configuration request after backup.
 * This source is not staged to a physical USB. No replacement database payload.
 * BSP imports resolve by name; private application API addresses come from the
 * exact supplied symbol maps. Build adds
 * checks against the exact function bytes from the supplied 5.43 firmware.
 */
#define SMEG_EMULATOR_ONLY_SET_WEB 1
#include "usb_backup_readonly.c"

typedef struct { unsigned int words[32]; } NativeObject;
static void *(*up_instance)(void);
static int (*up_get)(void *,const void *,const void *,void *);
static int (*up_set)(void *,const void *);
static void (*string_ctor)(void *,const char *,int,int,int);
static void (*string_dtor)(void *);
static void (*keys_ctor)(void *);
static void (*keys_dtor)(void *);
static int (*key_bool)(const void *,const void *,const void *,unsigned char *,int);
static int (*add_bool)(void *,const void *,const void *,int,int);
static int (*key_count)(const void *);

#include "usb_up_api_fingerprints.h"

static unsigned int fingerprint(const void *ptr, unsigned int count)
{
    const unsigned char *p = ptr;
    unsigned int h = 2166136261u;
    while (count--) h = (h ^ *p++) * 16777619u;
    return h;
}

int smeg_emulator_set_web(void)
{
    NativeObject section, name, old, request, verify;
    unsigned char before = 0, after = 0;
    void *up;
    int status = -1, initialized = 0;
    unsigned int i;
    const void *functions[10];
    unsigned int profile, matched = 0;
    FILE *log = fopen("/bd0/SMEG_BACKUP/change.txt", "wb");
    if (!log) return -20;
    fprintf(log, "EXPERIMENTAL QEMU-ONLY SINGLE-KEY REQUEST\n");
    /* The boot loader exports BSP symbols but not the application's private
     * C++ symbols. Use addresses from the exact supplied firmware symbol maps,
     * accepting a profile only if ALL function fingerprints match in RAM. */
    for(profile=0;profile<2;++profile) {
        matched=1;
        for(i=0;i<sizeof(api_checks)/sizeof(api_checks[0]);++i) {
            unsigned int addr=profile?api_checks[i].audio_address:api_checks[i].nav_address;
            unsigned int expected=profile?api_checks[i].audio_hash:api_checks[i].nav_hash;
            functions[i]=(const void *)addr;
            if(fingerprint(functions[i],api_checks[i].bytes)!=expected) { matched=0;break; }
        }
        if(matched) break;
    }
    if(!matched) {
        fprintf(log,"ABORT no exact supported firmware API profile matches; no setter called\n");
        fclose(log);return -21;
    }
    fprintf(log,"VERIFIED_API_PROFILE %s functions=%u\n",profile?"AUDIO_BT_256_5.43":"NAV_5.43",i);
    up_instance=(void *(*)(void))functions[0];
    up_get=(int (*)(void *,const void *,const void *,void *))functions[1];
    up_set=(int (*)(void *,const void *))functions[2];
    string_ctor=(void (*)(void *,const char *,int,int,int))functions[3];
    keys_ctor=(void (*)(void *))functions[4];
    key_bool=(int (*)(const void *,const void *,const void *,unsigned char *,int))functions[5];
    add_bool=(int (*)(void *,const void *,const void *,int,int))functions[6];
    key_count=(int (*)(const void *))functions[7];
    keys_dtor=(void (*)(void *))functions[8];
    string_dtor=(void (*)(void *))functions[9];
    up = up_instance();
    if (!up) { fprintf(log, "ABORT UP instance unavailable\n"); fclose(log); return -22; }
    string_ctor(&section, "internet", -1, 0, 1);
    string_ctor(&name, "Web_active", -1, 0, 1);
    keys_ctor(&old); keys_ctor(&request); keys_ctor(&verify); initialized = 1;
    {
      int get_status=up_get(up,&section,&name,&old), count=key_count(&old);
      int bool_status=key_bool(&old,&section,&name,&before,0);
      fprintf(log,"GET status=%d keys=%d bool_status=%d value=%u\n",get_status,count,bool_status,(unsigned int)before);
      if (get_status == -1 || count != 1 || bool_status != 0) {
        fprintf(log, "ABORT exact existing bool key not readable\n"); goto done;
      }
    }
    fprintf(log, "BEFORE internet.Web_active.0=%u\n", (unsigned int)before);
    if (before == 1) { fprintf(log,"UNCHANGED already enabled; setter not called\n"); status = 0; goto done; }
    if (before != 0 || !add_bool(&request,&section,&name,1,0) || key_count(&request) != 1) {
        fprintf(log, "ABORT one-key request validation failed\n"); goto done;
    }
    status = up_set(up,&request);
    fprintf(log, "NATIVE_SET_CONFIG_KEYS_IMMEDIATE status=%d request_keys=%d\n", status,key_count(&request));
    if (status == -1 || up_get(up,&section,&name,&verify) == -1 ||
        key_bool(&verify,&section,&name,&after,0) != 0 || after != 1) {
        fprintf(log, "FAILED readback; original complete file is on USB; inspect before any further action\n");
        status = -23; goto done;
    }
    fprintf(log,"AFTER internet.Web_active.0=%u\nFINISHED native one-key save; no automatic reboot\n",(unsigned int)after);
done:
    printf("SMEG_SANDBOX_WEB_RESULT status=%d before=%u after=%u\n",
           status,(unsigned int)before,(unsigned int)after);
    if (initialized) {
        keys_dtor(&verify); keys_dtor(&request); keys_dtor(&old);
        string_dtor(&name); string_dtor(&section);
    }
    fflush(log); fclose(log);
    return status;
}
