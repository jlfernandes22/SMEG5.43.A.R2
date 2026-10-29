#!/usr/bin/env python3
"""Inject USB read/open/close faults into the exact shared pre-erase verifier."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import zlib
import argparse
import re

ROOT = Path(__file__).resolve().parents[1]
HARNESS = r'''
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
static const char *mode, *check_log;
static int attempts, reads, log_closes, log_flushes, source_is_open, verified_sources;
static FILE *source_open(const char *p, const char *m) {
    FILE *f;
    ++attempts; reads=0;
    if (!strcmp(mode,"missing")) { errno=ENOENT; return NULL; }
    f=fopen(p,m);source_is_open=f!=NULL;return f;
}
static size_t source_read(void *p,size_t s,size_t n,FILE *f) {
    size_t got;
    if ((!strcmp(mode,"short") || !strcmp(mode,"ioerror")) && reads) return 0;
    got=fread(p,s,n,f);
    if (!reads && got && (!strcmp(mode,"bad") || (!strcmp(mode,"transient") && attempts==1)))
        ((unsigned char *)p)[0]^=1;
    ++reads; return got;
}
static int source_error(FILE *f) {
    if (!strcmp(mode,"ioerror")) { errno=EIO; return 1; }
    return ferror(f);
}
static int source_close(FILE *f) {
    int r=fclose(f);source_is_open=0;
    if (!strcmp(mode,"close")) { errno=EIO; return EOF; }
    return r;
}
static int source_errno(void) {return errno;}
static int source_delay(int ticks) {(void)ticks;return 0;}
static FILE *observed_log_open(const char *path,const char *access) {
    if(source_is_open){fprintf(stderr,"USB receipt opened during source read\n");abort();}
    return fopen(path,access);
}
struct ResourceFile {const char *path;unsigned bytes;};
static struct ResourceFile resource_files[2];
#define RESOURCE_COUNT 2u
static int theme_progress_percent(unsigned);
static int theme_progress_detail(const char *);
#define READONLY_PROGRESS_LOG check_log
#define fopen observed_log_open
#include "exact_progress.h"
#undef fopen
struct Event {unsigned percent,done,total,source_open;};
static struct Event events[102];
static unsigned event_count;
static int theme_progress_percent(unsigned percent) {
    if(!strcmp(mode,"progressfail") && percent>0)return -1;
    if(!strcmp(mode,"progressstartfail") && !percent)return -1;
    if(percent>100 || event_count>=102 || (event_count && percent<=events[event_count-1].percent))abort();
    if(percent==100 && (source_is_open || verified_sources!=2))abort();
    events[event_count++]=(struct Event){percent,readonly_done,readonly_total,(unsigned)source_is_open};
    return 0;
}
static int theme_progress_detail(const char *text) {(void)text;return 0;}
#define RESOURCE_CHECK_LOG check_log
#define RESOURCE_SOURCE_OPEN source_open
#define RESOURCE_SOURCE_READ source_read
#define RESOURCE_SOURCE_ERROR source_error
#define RESOURCE_SOURCE_CLOSE source_close
#define RESOURCE_SOURCE_ERRNO source_errno
#define RESOURCE_SOURCE_DELAY source_delay
static int test_log_error(FILE *f) {return !strcmp(mode,"logerror")?1:ferror(f);}
static int log_flush(FILE *f) {
    int r=fflush(f);++log_flushes;
    if(!strcmp(mode,"logflush") || (!strcmp(mode,"logflushsecond") && log_flushes==2))return EOF;
    return r;
}
static int log_close(FILE *f) {int r=fclose(f);++log_closes;return !strcmp(mode,"logclose")?EOF:r;}
#define RESOURCE_LOG_OPEN observed_log_open
#define RESOURCE_LOG_ERROR test_log_error
#define RESOURCE_LOG_FLUSH log_flush
#define RESOURCE_LOG_CLOSE log_close
#define RESOURCE_CHECK_BYTES readonly_progress_bytes
#define RESOURCE_CHECK_RESULT readonly_progress_result
#include "crc_table.h"
#include "theme_source_verify.h"
int main(int argc,char **argv) {
    unsigned bytes,crc,i; int result;
    if(argc==4 && !strcmp(argv[1],"--threshold")){
        printf("%u\n",readonly_threshold((unsigned)strtoul(argv[2],0,10),(unsigned)strtoul(argv[3],0,10)));return 0;
    }
    if(argc!=8)return 2;
    mode=argv[1];check_log=argv[3];bytes=(unsigned)strtoul(argv[4],0,10);crc=(unsigned)strtoul(argv[5],0,16);
    if(!strcmp(mode,"oversize")) --bytes;
    resource_files[0]=(struct ResourceFile){argv[2],bytes};
    resource_files[1]=(struct ResourceFile){argv[7],bytes};
    result=readonly_progress_start();
    for(i=0;!result && i<2;++i){result=check_source(resource_files[i].path,bytes,crc);if(!result)++verified_sources;}
    if(!result)result=theme_progress_percent(100);
    printf("{\"status\":%d,\"attempts\":%d,\"aligned\":%s,\"progress\":[",result,attempts,
        (uintptr_t)resource_source_buffer%64==0?"true":"false");
    for(i=0;i<event_count;++i)printf("%s{\"percent\":%u,\"done\":%u,\"total\":%u,\"source_open\":%u}",
        i?",":"",events[i].percent,events[i].done,events[i].total,events[i].source_open);
    printf("]}\n");
    if(source_is_open)return 4;
    if(strcmp(mode,"logfail") && log_closes!=attempts)return 3;
    return ((result==0)==(atoi(argv[6])!=0))?0:1;
}
'''

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=ROOT/'artifacts/phase21/verifier-byte-progress-tests.json')
    args=parser.parse_args()
    results=[]
    with tempfile.TemporaryDirectory(prefix='smeg-verifier-test-') as td:
        temp=Path(td);data=bytes(range(256))*4096
        source=temp/'bank.bin';source.write_bytes(data)
        second=temp/'bank2.bin';second.write_bytes(data)
        # Exercise the actual production progress implementation, not a
        # separately reimplemented test model.
        wrapper=(ROOT/'emulation/usb_theme_retry_readonly.c').read_text()
        model=wrapper.split('/* REAL_BYTE_PROGRESS_BEGIN',1)[1].split('/* REAL_BYTE_PROGRESS_END */',1)[0]
        model=model.split('*/',1)[1]
        (temp/'exact_progress.h').write_text(model)
        table=[]
        for i in range(256):
            n=i
            for _ in range(8):n=(n>>1)^(0xedb88320 if n&1 else 0)
            table.append(n)
        (temp/'crc_table.h').write_text('static const unsigned resource_crc_table[256]={'+','.join(hex(n)+'u'for n in table)+'};')
        (temp/'test.c').write_text(HARNESS)
        executable=temp/'test'
        subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
            '-I',str(temp),'-I',str(ROOT/'emulation'),str(temp/'test.c'),'-o',str(executable)],check=True)
        for case,success,attempts in [('clean',True,4),('transient',True,5),('bad',False,3),
                ('short',False,3),('ioerror',False,3),('close',False,3),('oversize',False,3),('missing',False,3),('logfail',False,1),('logerror',False,1),('logflush',False,1),('logclose',False,1),('logflushsecond',False,2),('progressfail',False,1),('progressstartfail',False,0)]:
            log=temp/(case+'.log') if case!='logfail' else temp/'missing-directory'/'log'
            run=subprocess.run([str(executable),case,str(source),str(log),str(len(data)),f'{zlib.crc32(data):08x}',str(int(success)),str(second)],
                check=False,text=True,capture_output=True,env=dict(os.environ,ASAN_OPTIONS="detect_leaks=0"))
            assert run.returncode==0,(case,run.stdout,run.stderr)
            r=json.loads(run.stdout);assert r['attempts']==attempts and r['aligned'],r
            source_checks=[]
            if log.exists():
                lines=log.read_text().splitlines()
                assert sum(line.startswith('SOURCE_CHECK ')for line in lines)==attempts
                for line in lines:
                    if line.startswith('SOURCE_CHECK '):
                        fields=dict(re.findall(r'(\w+)=(\S+)',line))
                        source_checks.append({key:int(fields[key])for key in ['attempt','opened','bytes','expected_bytes','ferror','fclose','consecutive','progress_error']})
                samples=[dict(zip(('bank','attempt','percent','done','total'),map(int,m.groups())))
                    for line in lines if(m:=re.fullmatch(r'BYTE_PROGRESS bank=(\d+) attempt=(\d+) percent=(\d+) done=(\d+) total=(\d+)',line))]
                assert all(p['percent']==p['done']*100//p['total'] and p['percent']<100 for p in samples)
                assert all(b['percent']>a['percent'] and b['done']>a['done']for a,b in zip(samples,samples[1:]))
            progress=r['progress']
            assert all(0<=p['percent']<=100 for p in progress)
            assert all(b['percent']>a['percent'] and b['done']>=a['done']for a,b in zip(progress,progress[1:]))
            assert bool(progress and progress[-1]['percent']==100)==success
            assert all(p['percent']<100 or not p['source_open'] for p in progress)
            if case=='clean':assert progress[-1]['done']==progress[-1]['total']==4*len(data)
            if case=='transient':
                assert progress[-1]['done']==progress[-1]['total']==5*len(data)
                assert [c['consecutive']for c in source_checks]==[0,1,2,1,2]
            results.append(dict(case=case,source_checks=source_checks,**r))
        # Exact threshold identities at real-bank scale and near uint32 max.
        threshold_count=0
        for total in [1,99,100,101,123080704,153505792,0xffffffff]:
            for percent in range(1,101):
                actual=int(subprocess.check_output([str(executable),'--threshold',str(total),str(percent)],env=dict(os.environ,ASAN_OPTIONS="detect_leaks=0")))
                assert actual==(total*percent+99)//100
                threshold_count+=1
    out=args.output.resolve();assert out.is_relative_to(ROOT/'artifacts')and not out.exists()
    out.write_text(json.dumps(dict(shared_implementation='emulation/theme_source_verify.h',progress_implementation='production block from emulation/usb_theme_retry_readonly.c',no_receipt_opens_during_source_reads=True,exact_threshold_cases=threshold_count,sanitizers=['address','undefined'],results=results),indent=2)+'\n')
    print(json.dumps([dict(case=r['case'],status=r['status'],attempts=r['attempts'],progress_samples=len(r['progress']))for r in results]))

if __name__=='__main__':main()
