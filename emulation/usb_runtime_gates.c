/* QEMU-only USB capability experiment. No settings or firmware-file writes.
 * Fixed, fingerprint-guarded RAM sites for AUDIO_BT_256 SMEG5.43.A.R2 only.
 * Reboot discards the changes. The sole file output is on virtual /bd0.
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
#include "usb_runtime_fingerprints.h"
static u32 ram_fingerprint(const void *,u32);
static void flush_text(u32);

/* Native relocatable loader ENTRY:YES enters text offset0. */
int smeg_usb_runtime_gates(void)
{
    const u32 sites[2]={0x0227f7b4u,0x04c171bcu};
    const u32 old[2]={0x409e0010u,0x7c630034u};
    const u32 replacement[2]={0x60000000u,0x38600020u};
    unsigned i,attempt;int matched=0;
    FILE *log;
    if(mkdir("/bd0/SMEG_RAM_PROBE",0777)!=0)return -1;
    log=fopen("/bd0/SMEG_RAM_PROBE/report.txt","wb");if(!log)return -2;
    fprintf(log,"QEMU ONLY: fixed INT_E checks in application RAM; no NAND/DB writes\n");
    for(attempt=0;attempt<300;++attempt){
        matched=1;
        for(i=0;i<sizeof(guards)/sizeof(guards[0]);++i)
            if(ram_fingerprint((const void *)guards[i].address,guards[i].length)!=guards[i].hash){matched=0;break;}
        if(matched)break;
        {int ticks=sysClkRateGet()/10;taskDelay(ticks>0?ticks:1);}
    }
    if(!matched){fprintf(log,"ABORT: exact application fingerprints not found; no RAM writes\n");fclose(log);return -3;}
    for(i=0;i<2;++i){
        u32 actual=*(volatile u32 *)sites[i];
        fprintf(log,"BEFORE address=%08x opcode=%08x expected=%08x\n",sites[i],actual,old[i]);
        if(actual!=old[i]){fprintf(log,"ABORT: unexpected instruction; no RAM writes\n");fclose(log);return -4;}
    }
    for(i=0;i<2;++i){*(volatile u32 *)sites[i]=replacement[i];flush_text(sites[i]);}
    for(i=0;i<2;++i){
        u32 actual=*(volatile u32 *)sites[i];
        fprintf(log,"AFTER address=%08x opcode=%08x expected=%08x\n",sites[i],actual,replacement[i]);
        if(actual!=replacement[i]){
            unsigned j;for(j=0;j<2;++j){*(volatile u32 *)sites[j]=old[j];flush_text(sites[j]);}
            fprintf(log,"FAILED: readback mismatch; original opcodes restored\n");fclose(log);return -5;
        }
    }
    fprintf(log,"FINISHED RAM_ONLY sites=2 persistent_changes=0 reboot_clears=1\n");
    fflush(log);fclose(log);return 0;
}

static u32 ram_fingerprint(const void *p,u32 count)
{
    const unsigned char *b=p;u32 h=2166136261u;
    while(count--)h=(h^*b++)*16777619u;
    return h;
}
static void flush_text(u32 address)
{
    /* e300 data->instruction cache synchronization, 32-byte cache line. */
    u32 line=address&~31u;
    __asm__ volatile("dcbst 0,%0; sync; icbi 0,%0; sync; isync"::"r"(line):"memory");
}
