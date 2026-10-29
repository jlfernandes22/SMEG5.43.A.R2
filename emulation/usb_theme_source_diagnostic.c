/* Read-only car-side file-source diagnostic. The only output is on /bd0.
 * No NAND/resource API, configuration setter, SQL, memory write or reboot.
 * Keep this entry first in .text for the stock relocatable USB loader.
 */
typedef unsigned size_t;
typedef void FILE;
extern FILE *fopen(const char*,const char*);
extern size_t fread(void*,size_t,size_t,FILE*);
extern int fclose(FILE*),fflush(FILE*),ferror(FILE*),mkdir(const char*,int);
extern int fprintf(FILE*,const char*,...),printf(const char*,...),errnoGet(void);
extern unsigned tickGet(void);
extern int sysClkRateGet(void);
#include "theme_source_diagnostic_contract.h"
static unsigned char bytes_buffer[8192] __attribute__((aligned(64)));
static int inspect(FILE*,const char*,unsigned,unsigned,unsigned,unsigned);
int smeg_theme_source_diagnostic(void)
{
    FILE *log;unsigned i,k,x,table_bad=0;int status=0;
    if(mkdir("/bd0/USB_DIAG",0777))return -1;
    log=fopen("/bd0/USB_DIAG/RESULT.TXT","wb");if(!log)return -2;
    fprintf(log,"READ_ONLY_THEME_SOURCE_DIAGNOSTIC v1\nNO_CAR_WRITES=1\nCLOCK_HZ=%d\n",sysClkRateGet());
    for(i=0;i<256;++i){x=i;for(k=0;k<8;++k)x=(x>>1)^((x&1)?0xedb88320u:0);if(x!=source_crc_table[i])++table_bad;}
    fprintf(log,"CRC_TABLE_REFERENCE_MISMATCHES=%u\n",table_bad);fflush(log);
    for(i=0;i<4;++i){const struct SourceCase*c=&source_cases[i];
        status=inspect(log,c->path,c->bytes,c->crc,c->fnv,1024);if(status<0)break;
    }
    if(!status){
        for(i=0;i<2;++i){const struct SourceCase*c=&source_cases[i*2];
            status=inspect(log,c->path,c->bytes,c->crc,c->fnv,8192);if(status<0)break;
        }
    }
    fprintf(log,"DIAGNOSTIC_COMPLETE status=%d\n",status);if(fflush(log)||fclose(log))return -3;
    printf("SMEG_READ_ONLY_SOURCE_DIAGNOSTIC_COMPLETE status=%d\n",status);return status;
}
static int inspect(FILE*log,const char*path,unsigned expected,unsigned expected_crc,unsigned expected_fnv,unsigned chunk)
{
    FILE*f;unsigned count=0,crc=~0u,fnv=2166136261u,iterations=0,short_reads=0,start=tickGet(),first=0;
    unsigned prefix_crc=~0u,prefix_count=0,next_progress=1048576u;size_t n,i;int io_error,read_errno,close_status,close_errno;
    fprintf(log,"BEGIN path=%s chunk=%u expected_bytes=%u expected_CRC32=%08x expected_FNV1A=%08x\n",path,chunk,expected,expected_crc,expected_fnv);fflush(log);
    f=fopen(path,"rb");
    if(!f){int e=errnoGet();fprintf(log,"OPEN_FAILED errno=%08x\n",(unsigned)e);return fflush(log)?-4:0;}
    while((n=fread(bytes_buffer,1,chunk,f))!=0){
        ++iterations;if(n<chunk)++short_reads;if(n>chunk){fprintf(log,"INVALID_READ_COUNT=%u\n",n);fclose(f);return -5;}
        if(!count&&n>=4)first=((unsigned)bytes_buffer[0]<<24)|((unsigned)bytes_buffer[1]<<16)|((unsigned)bytes_buffer[2]<<8)|bytes_buffer[3];
        for(i=0;i<n;++i){unsigned v=bytes_buffer[i];crc=(crc>>8)^source_crc_table[(crc^v)&255u];fnv=(fnv^v)*16777619u;
            if(prefix_count<65536u){unsigned bit;prefix_crc^=v;for(bit=0;bit<8;++bit)prefix_crc=(prefix_crc>>1)^((prefix_crc&1)?0xedb88320u:0);++prefix_count;}}
        count+=n;
        if(count>=next_progress){fprintf(log,"READ_PROGRESS bytes=%u CRC32=%08x\n",count,~crc);if(fflush(log)){fclose(f);return -4;}next_progress+=1048576u;}
        if(count>expected){fprintf(log,"OVERSIZE_STOP=1\n");break;}
    }
    io_error=ferror(f);read_errno=errnoGet();close_status=fclose(f);close_errno=errnoGet();
    fprintf(log,"END bytes=%u CRC32=%08x FNV1A=%08x ferror=%d read_errno=%08x fclose=%d close_errno=%08x reads=%u short_reads=%u first4=%08x elapsed_ticks=%u prefix_bytes=%u prefix_bitwise_CRC32=%08x\n",count,~crc,fnv,io_error,(unsigned)read_errno,close_status,(unsigned)close_errno,iterations,short_reads,first,tickGet()-start,prefix_count,~prefix_crc);
    fprintf(log,"SOURCE_MATCH=%d\n",!io_error&&!close_status&&count==expected&&~crc==expected_crc&&fnv==expected_fnv);
    return fflush(log)?-4:0;
}
