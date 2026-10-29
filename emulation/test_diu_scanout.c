/* Host harness: rendering code is generated directly from smeg_diu.h. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct { unsigned width,height,stride; uint8_t *data; } DisplaySurface;
typedef struct { DisplaySurface surface; unsigned updates; } Console;
typedef struct {
    size_t ram_size; uint8_t *ram; uint32_t regs[0x2200/4]; Console *diu_console;
    size_t diu_fast_bytes; uint8_t *diu_fast_cache; bool diu_fast_valid;
    DisplaySurface *diu_fast_surface;
    unsigned diu_fast_plane,diu_fast_width,diu_fast_height;
    uint32_t diu_fast_background;
} SmegMachineState;
#define MACHINE(s) (s)
#define MEMTXATTRS_UNSPECIFIED 0
#define MEMTX_OK 0
#define g_realloc realloc
#define g_malloc malloc
static void autofree(void *p) { free(*(void **)p); }
#define g_autofree __attribute__((cleanup(autofree)))
static int address_space_memory;
static uint8_t *guest_ram;
static size_t guest_size;
static unsigned ram_reads;
static bool fail_read;
static int address_space_read(void *as, uint64_t address, int attrs, void *out, size_t n)
{
    (void)as; (void)attrs; ram_reads++;
    if(fail_read || address > guest_size || n > guest_size-address) return 1;
    memcpy(out,guest_ram+address,n); return MEMTX_OK;
}
static uint32_t ldl_le_p(const uint8_t *p)
{ return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24; }
static void store(uint8_t *p,uint32_t v)
{ for(unsigned i=0;i<4;i++) p[i]=(uint8_t)(v>>(8*i)); }
static uint32_t smeg_reg_get(SmegMachineState *s,unsigned offset,unsigned size)
{ assert(size==4); return s->regs[offset/4]; }
static const uint8_t *memory_region_get_ram_ptr(uint8_t *p) { return p; }
static DisplaySurface *qemu_console_surface(Console *c) { return &c->surface; }
static unsigned surface_width(DisplaySurface *s) { return s->width; }
static unsigned surface_height(DisplaySurface *s) { return s->height; }
static unsigned surface_bits_per_pixel(DisplaySurface *s) { (void)s;return 32; }
static unsigned surface_stride(DisplaySurface *s) { return s->stride; }
static uint8_t *surface_data(DisplaySurface *s) { return s->data; }
static void qemu_console_resize(Console *c,unsigned w,unsigned h)
{
    free(c->surface.data);
    c->surface=(DisplaySurface){w,h,w*4+16,NULL};
    c->surface.data=calloc(h,c->surface.stride); assert(c->surface.data);
}
static void dpy_gfx_update(Console *c,int x,int y,unsigned w,unsigned h)
{ assert(x==0&&y==0&&w==c->surface.width&&h==c->surface.height);c->updates++; }
#include "diu_production.inc"
static SmegMachineState fast,reference;
static Console fc,rc;
static unsigned checks, fast_reads;
static uint32_t random_state=0x8caf1293;
static uint32_t rng(void)
{ random_state^=random_state<<13;random_state^=random_state>>17;random_state^=random_state<<5;return random_state; }
static void reg(unsigned offset,uint32_t value)
{ fast.regs[offset/4]=reference.regs[offset/4]=value; }
static void descriptor(unsigned plane,unsigned w,unsigned h)
{
    uint8_t *d=guest_ram+0x100+plane*64;
    memset(d,0,40);store(d,0x06338888);store(d+4,0x10000+plane*0x10000);
    store(d+8,(h<<12)|w);store(d+12,(h<<16)|w);
    store(d+24,0);store(d+28,0xffffff);
    reg(0x2100+plane*4,0x100+plane*64);
}
static void setup(unsigned plane,unsigned w,unsigned h)
{
    for(unsigned i=0;i<3;i++)reg(0x2100+4*i,0);
    reg(0x211c,1);reg(0x2128,(h<<16)|w);reg(0x2120,rng()&0xffffff);
    descriptor(plane,w,h);
    for(unsigned i=0;i<w*h;i++)store(guest_ram+0x10000+plane*0x10000+4*i,rng());
}
static void compare(void)
{
    ram_reads=0;smeg_diu_update(&fast);fast_reads=ram_reads;
    smeg_diu_reference(&reference);
    assert(fc.surface.width==rc.surface.width&&fc.surface.height==rc.surface.height);
    assert(fc.surface.stride==rc.surface.stride);
    if(memcmp(fc.surface.data,rc.surface.data,fc.surface.stride*fc.surface.height)) {
        fprintf(stderr,"DIU mismatch frame=%u size=%ux%u fastvalid=%u updates=%u/%u\n",
                checks,fc.surface.width,fc.surface.height,fast.diu_fast_valid,fc.updates,rc.updates);
        abort();
    }
    checks++;
}
int main(void)
{
    guest_size=4*1024*1024;guest_ram=calloc(1,guest_size);assert(guest_ram);
    fast.ram=reference.ram=guest_ram;fast.ram_size=reference.ram_size=guest_size;
    fast.diu_console=&fc;reference.diu_console=&rc;
    for(unsigned plane=0;plane<3;plane++)for(unsigned run=0;run<60;run++) {
        unsigned w=1+rng()%49,h=1+rng()%31;setup(plane,w,h);compare();
        assert(fast.diu_fast_valid);
        unsigned updates=fc.updates;ram_reads=0;compare();
        assert(fc.updates==updates); /* actual unchanged fast path skips display update */
        /* Descriptor is re-read, even when the cached bitmap has not changed. */
        assert(fast_reads==1);
        reg(0x2120,rng()&0xffffff);compare();assert(fc.updates==updates+1);
        uint8_t *p=guest_ram+0x10000+plane*0x10000+4*(rng()%(w*h));
        p[0]^=255;p[3]=(run%3==0)?0:(run%3==1)?255:127;
        compare();assert(fc.updates==updates+2);
    }
    /* Same pixels at another source/descriptor address must remain valid. */
    setup(2,13,11);compare();
    memcpy(guest_ram+0x50000,guest_ram+0x30000,13*11*4);
    store(guest_ram+0x180+4,0x50000);compare();
    /* Cache cannot survive fallback, bad RAM range, or descriptor read error. */
    for(unsigned reason=0;reason<10;reason++) {
        setup(1,17,19);compare();assert(fast.diu_fast_valid);
        uint8_t saved[40];memcpy(saved,guest_ram+0x140,40);
        if(reason==0)store(guest_ram+0x140,0x06338887); /* component format */
        if(reason==1)store(guest_ram+0x140+24,0xffffff),store(guest_ram+0x140+28,0); /* chromakey */
        if(reason==2)store(guest_ram+0x140+4,(uint32_t)guest_size-4); /* range */
        if(reason==3)store(guest_ram+0x140+12,0x80000000|(19<<16)|17); /* vertical flip */
        if(reason==4)store(guest_ram+0x140+32,0x1c0),memcpy(guest_ram+0x1c0,saved,40); /* area chain */
        if(reason==5)descriptor(2,17,19); /* multiple planes */
        if(reason==6)store(guest_ram+0x140+16,1); /* invalid source AOI */
        if(reason==7)fail_read=true;
        if(reason==8)store(guest_ram+0x140+12,0x40000000|(19<<16)|17); /* horizontal flip */
        if(reason==9)store(guest_ram+0x140+12,(18<<16)|16),store(guest_ram+0x140+20,(1<<16)|1); /* clipped AOI */
        compare();assert(!fast.diu_fast_valid);
        fail_read=false;reg(0x2108,0);memcpy(guest_ram+0x140,saved,40);
        unsigned updates=fc.updates;compare();assert(fast.diu_fast_valid&&fc.updates==updates+1);
    }
    /* Alpha extrema are tested explicitly on each overlay and base plane. */
    for(unsigned plane=0;plane<3;plane++)for(unsigned alpha=0;alpha<256;alpha++) {
        setup(plane,1,1);store(guest_ram+0x10000+plane*0x10000,(alpha<<24)|0x9b35f7);compare();
    }
    /* Resized host surface forces a new valid presentation. */
    setup(0,17,19);compare();qemu_console_resize(&fc,1,1);compare();
    free(fc.surface.data);free(rc.surface.data);free(fast.diu_fast_cache);
    free(reference.diu_fast_cache);free(guest_ram);
    printf("Production DIU fast/reference equality passed: %u frames, random RGBA, all alpha values, cache idle/revalidation and fallback cases\n",checks);
}
