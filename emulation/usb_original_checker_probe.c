/* Read-only verification of the exact extracted original CRC checker.
 * Only USB output files are opened for writing. No setters, flash erase,
 * flash program, preview installation or reboot entry points are included.
 */
typedef unsigned size_t;typedef void FILE;
extern FILE*fopen(const char*,const char*);
extern size_t fread(void*,size_t,size_t,FILE*);
extern int fclose(FILE*),fflush(FILE*),ferror(FILE*),mkdir(const char*,int);
extern int fprintf(FILE*,const char*,...),printf(const char*,...),errnoGet(void),sysClkRateGet(void);
extern unsigned tickGet(void);
extern int original_check_source(const char*,unsigned,unsigned);
extern unsigned char original_source_buffer[1024],original_context_data[],original_source_guard[8192];
#include "original_checker_contract.h"
static unsigned char aligned_source[1024] __attribute__((aligned(64)));
static unsigned char preheader_area[8192] __attribute__((aligned(64)));
static unsigned hash(const void*,unsigned);
static void companion(FILE*,const char*,unsigned char*);
static int checkpoint(FILE**);
static void guard_reset(void);
static unsigned guard_changes(void);
int smeg_original_checker_probe(void)
{
    FILE*log;unsigned before,after,i,b,start;int result;
    int(*read_pre)(int,void*)=(int(*)(int,void*))0x25f068u;
    if(mkdir("/bd0/CKDIAG",0777))return -1;
    log=fopen("/bd0/CKDIAG/RESULT.TXT","wb");if(!log)return -2;
    before=hash(original_context_data,ORIGINAL_DATA_BYTES);
    fprintf(log,"ORIGINAL_CHECKER_READ_ONLY_PROBE v1\nCLOCK_HZ=%d\nLEGACY_BUFFER=%08x MOD64=%u\nALIGNED_BUFFER=%08x MOD64=%u\nCONSTANT_DATA_FNV=%08x EXPECTED=%08x\n",sysClkRateGet(),(unsigned)original_source_buffer,(unsigned)original_source_buffer&63u,(unsigned)aligned_source,(unsigned)aligned_source&63u,before,ORIGINAL_DATA_FNV);
    if(before!=ORIGINAL_DATA_FNV){fprintf(log,"ABORT immutable original data mismatch\n");goto done;}
    guard_reset();start=tickGet();result=original_check_source(SOURCE_PATH,SOURCE_BYTES,SOURCE_CRC);
    fprintf(log,"ORIGINAL_BEFORE_HEADER_READS status=%d ticks=%u guard_changed=%u\n",result,tickGet()-start,guard_changes());if(checkpoint(&log))return -3;
    if(hash((const void*)0x25f068u,64)!=0x93bc6c98u){fprintf(log,"ABORT native read API fingerprint mismatch\n");goto done;}
    for(b=1;b<=2;++b){unsigned changed=0,first=8192,last=0;
        for(i=0;i<sizeof(preheader_area);++i)preheader_area[i]=0xa5;
        result=read_pre((int)b,preheader_area);
        for(i=168;i<sizeof(preheader_area);++i)if(preheader_area[i]!=0xa5){++changed;if(first==8192)first=i;last=i;}
        fprintf(log,"NATIVE_HEADER bank=%u status=%d hash=%08x expected=%08x guard_changed_bytes=%u guard_first=%u guard_last=%u\n",b,result,hash(preheader_area,168),b==1?0x0aa3195eu:0x061a55f7u,changed,first,last);
        if(result){fprintf(log,"ABORT native header read failed\n");goto done;}
    }
    after=hash(original_context_data,ORIGINAL_DATA_BYTES);fprintf(log,"CONSTANT_DATA_AFTER_NATIVE_READS=%08x unchanged=%d\n",after,after==before);if(checkpoint(&log))return -3;
    guard_reset();start=tickGet();result=original_check_source(SOURCE_PATH,SOURCE_BYTES,SOURCE_CRC);
    fprintf(log,"ORIGINAL_AFTER_HEADER_READS status=%d ticks=%u guard_changed=%u\n",result,tickGet()-start,guard_changes());if(checkpoint(&log))return -3;
    guard_reset();companion(log,"LEGACY_BUFFER",original_source_buffer);fprintf(log,"LEGACY_BUFFER_GUARD_CHANGED=%u\n",guard_changes());if(checkpoint(&log))return -3;
    companion(log,"ALIGNED_BUFFER",aligned_source);
done:
    fprintf(log,"ORIGINAL_CHECKER_PROBE_COMPLETE\n");if(fflush(log)){fclose(log);return -4;}if(fclose(log))return -4;
    printf("SMEG_ORIGINAL_CHECKER_READ_ONLY_COMPLETE\n");return 0;
}
static unsigned hash(const void*p,unsigned n){const unsigned char*b=p;unsigned h=2166136261u;while(n--)h=(h^*b++)*16777619u;return h;}
static int checkpoint(FILE**p){int bad=fflush(*p);if(fclose(*p))bad=1;*p=0;if(bad)return -1;*p=fopen("/bd0/CKDIAG/RESULT.TXT","ab");return *p?0:-1;}
static void companion(FILE*log,const char*name,unsigned char*buf)
{
    FILE*f=fopen(SOURCE_PATH,"rb");unsigned crc=~0u,nbytes=0,fnv=2166136261u,start=tickGet();const unsigned*table=(const unsigned*)(original_context_data+ORIGINAL_CRC_TABLE_OFFSET);size_t n,i;int ferr,err,closed;
    if(!f){fprintf(log,"COMPANION %s OPEN_FAILED errno=%08x\n",name,(unsigned)errnoGet());return;}
    while((n=fread(buf,1,1024,f))!=0){if(n>1024){fprintf(log,"INVALID_READ_COUNT=%u\n",n);break;}for(i=0;i<n;++i){crc=(crc>>8)^table[(crc^buf[i])&255u];fnv=(fnv^buf[i])*16777619u;}nbytes+=n;if(nbytes>SOURCE_BYTES)break;}
    ferr=ferror(f);err=errnoGet();closed=fclose(f);
    fprintf(log,"COMPANION %s bytes=%u CRC32=%08x FNV1A=%08x ferror=%d errno=%08x fclose=%d ticks=%u SOURCE_MATCH=%d\n",name,nbytes,~crc,fnv,ferr,(unsigned)err,closed,tickGet()-start,nbytes==SOURCE_BYTES&&~crc==SOURCE_CRC&&fnv==SOURCE_FNV&&!ferr&&!closed);
}

static void guard_reset(void){unsigned i;for(i=0;i<8192;++i)original_source_guard[i]=0xa5;}
static unsigned guard_changes(void){unsigned i,n=0;for(i=0;i<8192;++i)if(original_source_guard[i]!=0xa5)++n;return n;}
