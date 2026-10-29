#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "emulation/smeg_dma_copy.h"
typedef struct { uint8_t mem[1024], fifo[512]; unsigned pos, reads, writes; } Model;
static int read_mem(void *opaque,uint32_t a,uint8_t *p,unsigned n)
{
    Model *m=opaque;m->reads++;
    if(a==4096){if(m->pos+n>512)return -1;memcpy(p,m->fifo+m->pos,n);m->pos+=n;}
    else {if(a+n>1024)return -1;memcpy(p,m->mem+a,n);}
    return 0;
}
static int write_mem(void *opaque,uint32_t a,const uint8_t *p,unsigned n)
{
    Model *m=opaque;m->writes++;
    if(a==4096){if(m->pos+n>512)return -1;memcpy(m->fifo+m->pos,p,n);m->pos+=n;}
    else {if(a+n>1024)return -1;memcpy(m->mem+a,p,n);}
    return 0;
}
int main(void)
{
    Model m={0};uint8_t buffer[64];uint32_t src=4096,dst=0;
    for(unsigned i=0;i<512;i++)m.fifo[i]=(i*13)^0x5a;
    for(unsigned i=0;i<8;i++)assert(!smeg_dma_copy_minor(&m,&src,&dst,4,32,0,32,64,buffer,read_mem,write_mem));
    assert(src==4096&&dst==512&&m.reads==128&&m.writes==16);
    assert(!memcmp(m.mem,m.fifo,512));
    /* Reverse asymmetric direction; fixed peripheral address with RAM stride. */
    m.pos=m.reads=m.writes=0;src=0;dst=4096;memset(m.fifo,0,512);
    for(unsigned i=0;i<8;i++)assert(!smeg_dma_copy_minor(&m,&src,&dst,32,4,32,0,64,buffer,read_mem,write_mem));
    assert(src==512&&dst==4096&&m.reads==16&&m.writes==128);
    assert(!memcmp(m.mem,m.fifo,512));
    src=0;dst=512;assert(!smeg_dma_copy_minor(&m,&src,&dst,2,2,2,2,64,buffer,read_mem,write_mem));
    assert(!memcmp(m.mem,m.mem+512,64));
    assert(smeg_dma_copy_minor(&m,&src,&dst,0,4,0,4,64,buffer,read_mem,write_mem)==-1);
    assert(smeg_dma_copy_minor(&m,&src,&dst,4,32,4,32,60,buffer,read_mem,write_mem)==-1);
    src=1023;dst=0;assert(smeg_dma_copy_minor(&m,&src,&dst,4,4,4,4,4,buffer,read_mem,write_mem)==-1);
    puts("eDMA staged minor loops: SD4->RAM32, RAM32->SD4, equal-width, byte preservation, strides and invalid/bus-error inputs passed");
}
