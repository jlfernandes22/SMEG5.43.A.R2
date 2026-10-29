/* Physical-car candidate: reads stock preheaders and USB inputs only.
 * No NAND programming, configuration setter, preview copy, or marker deletion.
 * Exact shared source verifier and temporary native UI helper are included.
 */
typedef unsigned size_t;
typedef void FILE;
extern FILE *fopen(const char *,const char *);
extern size_t fread(void *,size_t,size_t,FILE *);
extern int fprintf(FILE *,const char *,...);
extern int snprintf(char *,size_t,const char *,...);
extern int fflush(FILE *);
extern int fclose(FILE *);
extern int ferror(FILE *);
extern int errnoGet(void);
extern int taskDelay(int);
extern int sysClkRateGet(void);
#include "theme_resource_contract.h"
static int theme_progress_begin(void);
static int theme_progress_step(const char *);
static int theme_progress_finish(int,const char *);
static int theme_progress_percent(unsigned);
static int theme_progress_detail(const char *);
static int check_source(const char *,unsigned,unsigned);
static int readonly_read_progress(const char *,unsigned);
static int readonly_progress_start(void);
static int readonly_progress_bytes(const char *,unsigned,unsigned,unsigned);
static int readonly_progress_result(const char *,unsigned,unsigned,unsigned,int,unsigned);
static unsigned readonly_hash(const void *,unsigned);
int smeg_theme_retry_readonly(void)
{
    unsigned i,bank;int status=0;FILE *f;
    static unsigned char pre[8192] __attribute__((aligned(64)));
    int (*read_pre)(int,void *)=(int (*)(int,void *))resource_api[0].address;
    f=fopen("/bd0/READCHECK.TXT","rb");
    if(f){fclose(f);return -161;}
    if(theme_progress_begin())return -162;
    if(readonly_progress_start()){status=-169;goto done;}
    f=fopen("/bd0/READCHECK.TXT","wb");
    if(!f){status=-163;goto done;}
    fprintf(f,"READ_ONLY_THEME_CHECK v2; real byte progress; no persistent car writes\n");
    status=fflush(f)?-164:0;if(fclose(f))status=-164;
    if(status)goto done;
    if(readonly_hash((const void *)resource_api[0].address,64)!=resource_api[0].hash){status=-165;goto done;}
    theme_progress_step("Check stock banks");
    for(bank=1;bank<=2;++bank){
        int native_status=read_pre((int)bank,pre);unsigned actual=readonly_hash(pre,168);
        f=fopen("/bd0/READCHECK.TXT","ab");
        if(!f){status=-167;goto done;}
        if(fprintf(f,"STOCK_PREHEADER bank=%u status=%d hash=%08x expected=%08x\n",bank,native_status,actual,original_pre_hash[bank-1])<0)status=-167;
        if(fflush(f))status=-167;
        if(fclose(f))status=-167;
        if(status)goto done;
        if(native_status || actual!=original_pre_hash[bank-1]){status=-166;goto done;}
    }
    for(i=0;i<RESOURCE_COUNT;++i){
        const struct ResourceFile *r=&resource_files[i];
        if(check_source(r->path,r->bytes,r->crc32)){status=-63;break;}
    }
 done:
    f=fopen("/bd0/READCHECK.TXT","ab");
    if(f){
        if(fprintf(f,"READ_ONLY_CHECK_RESULT status=%d\n",status)<0)status=-167;
        if(fflush(f))status=-167;
        if(fclose(f))status=-167;
    }else status=-167;
    /* A complete input file is not success until its CRC, close, consecutive
     * passes and final result receipt have all succeeded. */
    if(!status && theme_progress_percent(100))status=-169;
    if(theme_progress_finish(status,status?"READ FAILED - USB log":"READ OK - remove USB") && !status)status=-168;
    return status;
}
#include "theme_install_progress.h"
#define RESOURCE_CHECK_LOG "/bd0/READCHECK.TXT"
#define RESOURCE_CHECK_PROGRESS(path,attempt) readonly_read_progress(path,attempt)
#define RESOURCE_CHECK_BYTES(path,attempt,count,expected) readonly_progress_bytes(path,attempt,count,expected)
#define RESOURCE_CHECK_RESULT(path,attempt,count,expected,matched,consecutive) readonly_progress_result(path,attempt,count,expected,matched,consecutive)
#include "theme_source_verify.h"

/* REAL_BYTE_PROGRESS_BEGIN -- compiled verbatim by the host fault harness. */
#ifndef READONLY_PROGRESS_LOG
#define READONLY_PROGRESS_LOG "/bd0/READCHECK.TXT"
#endif
struct ReadonlyProgressSample {unsigned bank,attempt,percent,done,total;};
static struct ReadonlyProgressSample readonly_samples[100];
static unsigned readonly_sample_count,readonly_flushed_samples;
static unsigned readonly_done,readonly_total,readonly_percent;
static unsigned readonly_attempt[RESOURCE_COUNT],readonly_count[RESOURCE_COUNT],readonly_retry[RESOURCE_COUNT];
static unsigned readonly_threshold(unsigned total,unsigned percent)
{
    /* Exact ceil(total*percent/100), without 64-bit runtime division imports.
     * Both products stay <= total (or <= 9900 for the remainder product). */
    return (total/100u)*percent+((total%100u)*percent+99u)/100u;
}
static int readonly_progress_emit(unsigned bank,unsigned attempt)
{
    unsigned next=readonly_percent;char message[64];
    while(next<99u && readonly_done>=readonly_threshold(readonly_total,next+1u))++next;
    if(next==readonly_percent)return 0;
    snprintf(message,sizeof(message),"USB %u%% - %u/%u KiB",next,readonly_done/1024u,readonly_total/1024u);
    if(theme_progress_detail(message) || theme_progress_percent(next))return -1;
    if(readonly_sample_count>=100u)return -1;
    readonly_samples[readonly_sample_count++]=(struct ReadonlyProgressSample){bank,attempt,next,readonly_done,readonly_total};
    readonly_percent=next;return 0;
}
static int readonly_progress_start(void)
{
    unsigned i;
    readonly_done=readonly_total=readonly_percent=readonly_sample_count=readonly_flushed_samples=0;
    for(i=0;i<RESOURCE_COUNT;++i){
        unsigned bytes=resource_files[i].bytes;
        if(!bytes || bytes>(~0u-readonly_total)/2u)return -1;
        readonly_total+=bytes*2u;
        readonly_attempt[i]=readonly_count[i]=readonly_retry[i]=0;
    }
    if(!readonly_total)return -1;
    return theme_progress_percent(0);
}
static unsigned readonly_progress_index(const char *path)
{
    unsigned i;
    /* check_source retains the caller's resource_files[i].path pointer. */
    for(i=0;i<RESOURCE_COUNT;++i)if(resource_files[i].path==path)return i;
    return RESOURCE_COUNT;
}
static int readonly_progress_bytes(const char *path,unsigned attempt,unsigned count,unsigned expected)
{
    unsigned i=readonly_progress_index(path),delta;
    if(i==RESOURCE_COUNT || expected!=resource_files[i].bytes || !attempt || attempt>3u)return -1;
    if(attempt<readonly_attempt[i])return -1;
    if(attempt!=readonly_attempt[i]){readonly_attempt[i]=attempt;readonly_count[i]=0;}
    if(count>expected)count=expected;
    if(count<readonly_count[i])return -1;
    delta=count-readonly_count[i];
    if(delta>~0u-readonly_done)return -1;
    readonly_done+=delta;readonly_count[i]=count;
    return readonly_progress_emit(i+1u,attempt);
}
static int readonly_progress_result(const char *path,unsigned attempt,unsigned count,unsigned expected,int matched,unsigned consecutive)
{
    unsigned i=readonly_progress_index(path),j;FILE *log;int bad=0;
    (void)count;(void)consecutive;
    if(i==RESOURCE_COUNT || expected!=resource_files[i].bytes || !attempt || attempt>3u)return -1;
    if(!matched && !readonly_retry[i] && attempt<3u){
        if(expected>~0u-readonly_total)return -1;
        readonly_total+=expected;readonly_retry[i]=1;
    }
    /* The denominator can grow after a failed read. Keep the display steady
     * until actual subsequent bytes cross its next threshold; never rewind. */
    if(readonly_progress_emit(i+1u,attempt))return -1;
    if(readonly_flushed_samples==readonly_sample_count)return 0;
    log=fopen(READONLY_PROGRESS_LOG,"ab");if(!log)return -1;
    for(j=readonly_flushed_samples;j<readonly_sample_count;++j){
        const struct ReadonlyProgressSample *p=&readonly_samples[j];
        if(fprintf(log,"BYTE_PROGRESS bank=%u attempt=%u percent=%u done=%u total=%u\n",
            p->bank,p->attempt,p->percent,p->done,p->total)<0){bad=1;break;}
    }
    if(ferror(log))bad=1;
    if(fflush(log))bad=1;
    if(fclose(log))bad=1;
    if(bad)return -1;
    readonly_flushed_samples=readonly_sample_count;return 0;
}
/* REAL_BYTE_PROGRESS_END */
static int readonly_read_progress(const char *path,unsigned attempt)
{
    char message[32];const char *name=path;const char *p=path;
    while(*p){if(*p=='/')name=p+1;++p;}
    snprintf(message,sizeof(message),"%.9s read %u/3",name,attempt);
    return theme_progress_step(message);
}
static unsigned readonly_hash(const void *v,unsigned n)
{const unsigned char *p=v;unsigned h=2166136261u;while(n--)h=(h^*p++)*16777619u;return h;}
