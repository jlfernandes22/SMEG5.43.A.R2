/* Host Mesa integration test: real pixels through guest PPC scalar/pointer ABI.
 * Run emulation/test_soft_gles.sh for C backend + official C++ decoder linkage.
 */
#define SMEG_SOFT_GLES_TEST
#include "smeg_soft_gles.c"
#include <time.h>
static uint32_t fb(void*p){(void)p;return 0x1000000;}
static unsigned presents;
static void present(void *opaque)
{
    (void)opaque;
    if (!presents++) {
        assert(test_ram[0x1000000] == 0 && test_ram[0x1000002] == 255);
    }
}
static void invoke(SoftGL*s,CPUPPCState*e,const char*n)
{for(size_t i=0;i<G_N_ELEMENTS(exports);i++)if(!strcmp(exports[i].name,n)){assert(match(s,exports[i].pc));bool handled=call(s,e,exports[i].pc);assert(handled||!strcmp(n,"glBindTexture"));if(!handled)e->nip=e->lr;assert(e->nip==e->lr);return;}assert(!"missingGLexport");}
static void fp(CPUPPCState*e,int n,double f){memcpy(&e->fpr[n],&f,8);}
static void test_memory_helpers(void)
{
    SoftGL s={.fast_memory=true};
    CPUPPCState e={.lr=0x01000300,.gpr[1]=0x1000};
    const uint32_t src=0x01001000,dst=0x01002000;
    for (unsigned i=0;i<128;i++) test_ram[src+i]=i;
    e.gpr[3]=dst;e.gpr[4]=src;e.gpr[5]=128;
    assert(match(&s,0x002cb648)&&call(&s,&e,0x002cb648));
    assert(e.gpr[3]==dst&&e.nip==e.lr&&e.gpr[1]==0x1000);
    assert(!memcmp(test_ram+src,test_ram+dst,128));
    uint8_t expected[128];memcpy(expected,test_ram+src,128);
    memmove(expected+5,expected,100);
    e.gpr[3]=src+5;e.gpr[4]=src;e.gpr[5]=100;
    assert(call(&s,&e,0x002cb684));
    assert(!memcmp(expected,test_ram+src,128));
    e.gpr[3]=dst;e.gpr[4]=0x1234;e.gpr[5]=128;
    assert(call(&s,&e,0x002cb6c0));
    for(unsigned i=0;i<128;i++)assert(test_ram[dst+i]==0x34);
    e.gpr[3]=src;e.gpr[4]=dst;e.gpr[5]=128;
    assert(call(&s,&e,0x002aa15c));
    assert(e.gpr[3]==src&&!memcmp(test_ram+src,test_ram+dst,128));
    e.nip=123;e.gpr[3]=0x00200000;e.gpr[4]=src;e.gpr[5]=32;
    assert(!call(&s,&e,0x002cb648)&&e.nip==123);
    e.gpr[3]=dst;e.gpr[4]=0x80001108;
    assert(!call(&s,&e,0x002cb648)&&e.nip==123);
    e.gpr[3]=0x1ffffff0;e.gpr[4]=src;
    assert(!call(&s,&e,0x002cb648)&&e.nip==123);
    e.gpr[3]=dst;e.gpr[4]=src;e.lr=0x00200100;
    assert(!call(&s,&e,0x002cb648)&&e.nip==123);
    assert(!s.attempted); /* Memory acceleration never initializes host GL. */
}
int main(void)
{
    test_memory_helpers();
    SoftGL s={.framebuffer=fb,.present=present};CPUPPCState e={.lr=0x123456,.gpr[1]=0x1000};
    const char *mode=getenv("SMEG_GL_RENDERER");
    char *prior_software=g_strdup(getenv("LIBGL_ALWAYS_SOFTWARE"));
    char *prior_vendor=g_strdup(getenv("__EGL_VENDOR_LIBRARY_FILENAMES"));
    fp(&e,1,1);fp(&e,2,0);fp(&e,3,0);fp(&e,4,1);invoke(&s,&e,"glClearColor");
    if(!mode||!strcmp(mode,"auto")) {
        assert(!g_strcmp0(prior_software,getenv("LIBGL_ALWAYS_SOFTWARE")));
        assert(!g_strcmp0(prior_vendor,getenv("__EGL_VENDOR_LIBRARY_FILENAMES")));
    } else assert(!strcmp(getenv("LIBGL_ALWAYS_SOFTWARE"),"1"));
    g_free(prior_software);g_free(prior_vendor);
    e.gpr[3]=GL_COLOR_BUFFER_BIT;invoke(&s,&e,"glClear");invoke(&s,&e,"eglSwapBuffers");
    assert(presents == 1);
    assert(test_ram[0x1000000]==0&&test_ram[0x1000002]==255&&test_ram[0x1000003]==255);
    e.gpr[3]=GL_MAX_TEXTURE_SIZE;e.gpr[4]=0x2000;invoke(&s,&e,"glGetIntegerv");assert(ldl_be_p(test_ram+0x2000)>=2048);
    e.gpr[3]=GL_RENDERER;assert(!call(&s,&e,0x01fcdd74)); /* Native stable GLES strings. */
    float vertices[]={-.8f,-.8f,.8f,-.8f,0,.8f};
    for(unsigned i=0;i<6;i++){uint32_t bits;memcpy(&bits,&vertices[i],4);stl_be_p(test_ram+0x3000+i*4,bits);}
    e.gpr[3]=2;e.gpr[4]=GL_FLOAT;e.gpr[5]=0;e.gpr[6]=0x3000;invoke(&s,&e,"glVertexPointer");
    e.gpr[3]=GL_VERTEX_ARRAY;invoke(&s,&e,"glEnableClientState");
    fp(&e,1,0);fp(&e,2,1);fp(&e,3,0);fp(&e,4,1);invoke(&s,&e,"glColor4f");
    e.gpr[3]=GL_TRIANGLES;e.gpr[4]=0;e.gpr[5]=3;invoke(&s,&e,"glDrawArrays");invoke(&s,&e,"eglSwapBuffers");
    unsigned center=0x1000000+(240*800+400)*4;assert(test_ram[center]==0&&test_ram[center+1]==255&&test_ram[center+2]==0);
    /* A relocated updater export shares the real renderer only after its
     * original instruction signature matches. Unknown code stays native. */
    s.upgrade_base=0x01080000;
    const UpgradeAlias *ua=NULL;
    for(size_t i=0;i<G_N_ELEMENTS(upgrade_aliases);i++)
        if(!strcmp(exports[upgrade_aliases[i].export_index].name,"glClearColor"))ua=&upgrade_aliases[i];
    assert(ua);
    uint32_t upc=s.upgrade_base+ua->offset;
    assert(match(&s,upc));
    memset(test_ram+upc,0,16);
    assert(!call(&s,&e,upc));
    for(unsigned i=0;i<4;i++)stl_be_p(test_ram+upc+4*i,ua->signature[i]);
    assert(call(&s,&e,upc));
    assert(resolve_export(&s,upc)==&exports[ua->export_index]);
    /* The native256 updater's matched exports have displacement+0x74.
     * Routing metadata can be changed while paused without touching code. */
    active_soft_gl=&s;
    assert(!smeg_soft_gles_set_upgrade_base(1));
    assert(smeg_soft_gles_set_upgrade_base(0x01080000));
    assert(smeg_soft_gles_get_upgrade_base()==0x01080000);
    s.bsp256=true;
    uint32_t upc256=upc+0x74;
    assert(!resolve_export(&s,upc));
    for(unsigned i=0;i<4;i++)stl_be_p(test_ram+upc256+4*i,ua->signature[i]);
    assert(call(&s,&e,upc256));
    test_ram[upc256]^=1;
    assert(!call(&s,&e,upc256));
    s.bsp256=false;active_soft_gl=NULL;
    s.upgrade_base=0;
    assert(!resolve_export(&s,upc));
    /* Ninth integer argument comes from guest stack+8; packed565 is BE. */
    stl_be_p(test_ram+0x4000,123);
    e.gpr[3]=GL_TEXTURE_2D;e.gpr[4]=ldl_be_p(test_ram+0x4000);invoke(&s,&e,"glBindTexture");
    uint32_t args[]={GL_TEXTURE_2D,0,GL_RGB,2,2,0,GL_RGB,GL_UNSIGNED_SHORT_5_6_5,0x5000};
    for(unsigned i=0;i<8;i++)e.gpr[3+i]=args[i];
    stl_be_p(test_ram+0x1008,args[8]);
    for(unsigned i=0;i<4;i++)stw_be_p(test_ram+0x5000+i*2,0xf800);
    invoke(&s,&e,"glTexImage2D");uint8_t tex[16]={0};glGetTexImage(GL_TEXTURE_2D,0,GL_RGBA,GL_UNSIGNED_BYTE,tex);assert(tex[0]==255&&tex[1]==0&&tex[2]==0);
    /* Vendor MM entry falls through original allocator; return hook captures
     * its real output before the Qt stack slot can be reused, then CPU fills. */
    args[2]=GL_BGRA;args[6]=GL_BGRA;args[7]=GL_UNSIGNED_BYTE;args[8]=0x6000;
    for(unsigned i=0;i<8;i++)e.gpr[3+i]=args[i];
    stl_be_p(test_ram+0x1008,args[8]);e.lr=0x01dfce0c;
    assert(!call(&s,&e,0x01fc8810)); /* No fake native allocation. */
    stl_be_p(test_ram+0x6000,0x7000);assert(!call(&s,&e,0x01dfce0c));
    for(unsigned i=0;i<4;i++){test_ram[0x7000+i*4]=255;test_ram[0x7003+i*4]=255;}
    assert(upload_native_textures(&e,&s));memset(tex,0,sizeof tex);
    glGetTexImage(GL_TEXTURE_2D,0,GL_RGBA,GL_UNSIGNED_BYTE,tex);
    assert(tex[0]==0&&tex[1]==0&&tex[2]==255&&tex[3]==255);
    e.gpr[3]=GL_TEXTURE_2D;e.gpr[4]=GL_TEXTURE_MIN_FILTER;e.gpr[5]=GL_NEAREST;
    invoke(&s,&e,"glTexParameterx");GLint filter=0;
    glGetTexParameteriv(GL_TEXTURE_2D,GL_TEXTURE_MIN_FILTER,&filter);assert(filter==GL_NEAREST);
    /* Actual primary decoder receives the original native MM allocation. */
    uint32_t compressed[]={GL_TEXTURE_2D,0,0x8c02,8,8,0,32,0x6000};
    for(unsigned i=0;i<8;i++)e.gpr[3+i]=compressed[i];
    e.lr=0x01dfc778;assert(!call(&s,&e,0x01fc8730));
    stl_be_p(test_ram+0x6000,0x9000);assert(!call(&s,&e,0x01dfc778));
    for(unsigned i=0;i<4;i++){memset(test_ram+0x9000+i*8,0,4);memset(test_ram+0x9004+i*8,255,4);}
    assert(upload_native_textures(&e,&s));uint8_t decoded[8*8*4];
    glGetTexImage(GL_TEXTURE_2D,0,GL_RGBA,GL_UNSIGNED_BYTE,decoded);
    for(unsigned i=0;i<sizeof decoded;i++)assert(decoded[i]==255);
    for(unsigned i=0;i<4;i++){test_ram[0x9004+i*8]=0;test_ram[0x9005+i*8]=0xfc;test_ram[0x9006+i*8]=0;test_ram[0x9007+i*8]=0xfc;}
    s.native_textures[0].uploaded=false;assert(upload_native_textures(&e,&s));
    glGetTexImage(GL_TEXTURE_2D,0,GL_RGBA,GL_UNSIGNED_BYTE,decoded);
    for(unsigned i=0;i<64;i++)assert(decoded[i*4]==255&&decoded[i*4+1]==0&&decoded[i*4+2]==0&&decoded[i*4+3]==255);
    /* Matrix has an x in its name even in the floating-point variant. */
    float matrix[16]={1,0,0,0,0,1,0,0,0,0,1,0,25,30,0,1};
    for(unsigned i=0;i<16;i++){uint32_t bits;memcpy(&bits,&matrix[i],4);stl_be_p(test_ram+0x8000+i*4,bits);}
    e.gpr[3]=GL_MODELVIEW;invoke(&s,&e,"glMatrixMode");
    e.gpr[3]=0x8000;invoke(&s,&e,"glLoadMatrixf");float actual[16];
    glGetFloatv(GL_MODELVIEW_MATRIX,actual);assert(actual[0]==1&&actual[5]==1&&actual[12]==25&&actual[13]==30);
    for(unsigned i=0;i<16;i++)stl_be_p(test_ram+0x8000+i*4,(int32_t)(matrix[i]*65536));
    e.gpr[3]=0x8000;invoke(&s,&e,"glLoadMatrixx");glGetFloatv(GL_MODELVIEW_MATRIX,actual);
    assert(actual[0]==1&&actual[5]==1&&actual[12]==25&&actual[13]==30);
    e.gpr[3]=UINT32_MAX;assert(!call(&s,&e,0x01fcdd74));assert(e.gpr[3]==UINT32_MAX);
    /* Interleaved BE attributes bulk-gather correctly; padding is not data. */
    Array interleaved={.address=0xa000,.size=2,.type=GL_FLOAT,.stride=20};
    for(unsigned i=0;i<6;i++){uint32_t bits;memcpy(&bits,&vertices[i],4);stl_be_p(test_ram+0xa000+(i/2)*20+(i%2)*4,bits);}
    void *gathered;GLenum gathered_type;
    unsigned long reads_before=test_reads;
    assert(array_data(&e,&interleaved,3,&gathered,&gathered_type));
    assert(gathered_type==GL_FLOAT&&!memcmp(gathered,vertices,sizeof vertices));g_free(gathered);
    if(!getenv("SMEG_GL_BASELINE"))assert(test_reads-reads_before==1);
    /* Distinct top/bottom colors and alpha prove flip and BGRA preservation. */
    glEnable(GL_SCISSOR_TEST);glScissor(0,0,800,240);glClearColor(.25f,.5f,.75f,.5f);glClear(GL_COLOR_BUFFER_BIT);
    glScissor(0,240,800,240);glClearColor(.75f,.25f,.5f,.25f);glClear(GL_COLOR_BUFFER_BIT);glDisable(GL_SCISSOR_TEST);
    unsigned long writes_before=test_writes;assert(swap(&e,&s));
    if(!getenv("SMEG_GL_BASELINE"))assert(test_writes-writes_before==1);
    const uint8_t *top=test_ram+fb(NULL),*bottom=top+479*3200;
    assert(abs(top[0]-128)<=1&&abs(top[1]-64)<=1&&abs(top[2]-191)<=1&&abs(top[3]-64)<=1);
    assert(abs(bottom[0]-191)<=1&&abs(bottom[1]-128)<=1&&abs(bottom[2]-64)<=1&&abs(bottom[3]-128)<=1);
    if(getenv("SMEG_GL_BENCHMARK")) {
        s.calls=256;s.draws=32;s.swaps=16;
        glMatrixMode(GL_MODELVIEW);glLoadIdentity();glMatrixMode(GL_PROJECTION);glLoadIdentity();
        e.gpr[3]=GL_TEXTURE_2D;invoke(&s,&e,"glDisable");
        struct timespec begin,end;clock_gettime(CLOCK_MONOTONIC,&begin);
        reads_before=test_reads;writes_before=test_writes;
        for(unsigned frame=0;frame<40;frame++) {
            for(unsigned d=0;d<150;d++) {
                fp(&e,1,d%2);fp(&e,2,1);fp(&e,3,0);fp(&e,4,1);invoke(&s,&e,"glColor4f");
                e.gpr[3]=GL_TRIANGLES;e.gpr[4]=0;e.gpr[5]=3;invoke(&s,&e,"glDrawArrays");
            }
            invoke(&s,&e,"eglSwapBuffers");
        }
        clock_gettime(CLOCK_MONOTONIC,&end);
        double milliseconds=(end.tv_sec-begin.tv_sec)*1000.+(end.tv_nsec-begin.tv_nsec)/1.e6;
        printf("BENCHMARK frames=40 draws=6000 ms=%.3f ms_per_frame=%.3f reads=%lu writes=%lu\n",milliseconds,milliseconds/40,test_reads-reads_before,test_writes-writes_before);
    }
    if(getenv("SMEG_GL_IDLE_BENCHMARK")) {
        s.calls=256;s.draws=32;s.swaps=16;s.trace_timing=true;
        glMatrixMode(GL_MODELVIEW);glLoadIdentity();glMatrixMode(GL_PROJECTION);glLoadIdentity();
        glDisable(GL_TEXTURE_2D);
        for(unsigned trial=0;trial<6;trial++) {
            struct timespec idle={.tv_sec=1};nanosleep(&idle,NULL);
            struct timespec begin,end;clock_gettime(CLOCK_MONOTONIC,&begin);
            for(unsigned d=0;d<150;d++) {
                glColor4f(d%2,1,0,1);
                assert(draw(&e,&s,GL_TRIANGLES,0,3,0,0));
            }
            assert(swap(&e,&s));clock_gettime(CLOCK_MONOTONIC,&end);
            double ms=(end.tv_sec-begin.tv_sec)*1000.+(end.tv_nsec-begin.tv_nsec)/1.e6;
            printf("IDLE_BENCHMARK trial=%u idle_ms=1000 draw_and_swap_ms=%.3f\n",trial,ms);
        }
    }
    assert(glGetError()==GL_NO_ERROR);puts("real Mesa PPC ABI clear/BEarray/get/string/packed565/stackarg/native-MM/framebuffer checks passed");return 0;
}
