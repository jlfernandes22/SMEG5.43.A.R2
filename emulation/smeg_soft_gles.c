/* Opt-in original-firmware GL API emulation using real host compatibility GL.
 * Guest code is untouched. Unsupported entry points stay native; never synthesize
 * successful draw completion or UI pixels. The context belongs to the vCPU thread.
 */
#ifdef SMEG_SOFT_GLES_TEST
#include "test_soft_gles_support.h"
#else
#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/cpu-common.h"
#include "exec/address-spaces.h"
#include "exec/tb-flush.h"
#include "qemu/timer.h"
#include "hw/ppc/smeg_api_hook.h"
#include "hw/ppc/smeg_soft_gles.h"
#endif
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GL/gl.h>
#include <GL/glext.h>
#include <ffi.h>
#include <dlfcn.h>
#include <math.h>
#include "powervr/smeg_pvrtc.h"

typedef struct Export { uint32_t pc; const char *name, *sig; } Export;
static const Export exports[] = {
#include "smeg_gles_symbols.inc"
};
typedef struct UpgradeAlias {
    uint32_t offset; unsigned export_index;
    uint32_t signature[4], mask[4];
} UpgradeAlias;
static const UpgradeAlias upgrade_aliases[] = {
#include "smeg_gles_upgrade_aliases.inc"
};
typedef struct Array { uint32_t address; unsigned size, type, stride; bool enabled; } Array;
typedef struct NativeTexture {
    uint32_t texture, target, level, width, height, format, type;
    uint32_t output, cpu, return_pc, entry_sp;
    bool uploaded, compressed;
    unsigned image_bytes;
} NativeTexture;
typedef struct ScalarCall {
    ffi_cif cif; ffi_type *types[16]; void *function;
    bool prepared;
} ScalarCall;
typedef struct SoftGL {
    EGLDisplay display; EGLContext context; EGLSurface surface;
    unsigned upgrade_calls;
    uint32_t upgrade_base; /* Observed native ELF .text base; host API routing only. */
    int32_t application_delta; /* Verified AUDIO_BT 5.43 export displacement. */
    bool bsp256, fast_module_memory;
    bool attempted, ready, trace_timing, fast_memory; unsigned unpack, pack, client_texture;
    Array vertex, color, normal, tex[4];
    uint32_t (*framebuffer)(void *); void *fbopaque;
    void (*present)(void *);
    unsigned unsupported, draws, swaps, calls;
    GLenum pending_error;
    ScalarCall scalar_calls[G_N_ELEMENTS(exports)];
    uint8_t *swap_pixels, *swap_flipped;
    int64_t frame_first_draw_ns;
    unsigned frame_draws;
    uint64_t memory_calls, memory_bytes;
    NativeTexture native_textures[256]; unsigned native_count;
} SoftGL;
static SoftGL *active_soft_gl;
#ifndef SMEG_SOFT_GLES_TEST
static CPUState *active_soft_gl_cpu;
static MemoryRegionCache api_ram_cache;
static bool api_ram_cached;
#endif
static int64_t host_time_ns(void)
{
#ifdef SMEG_SOFT_GLES_TEST
    return g_get_monotonic_time()*1000;
#else
    /* Same clock domain as board MCU input edge and DMA timing traces. */
    return qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
#endif
}
static bool guest(CPUPPCState *env, uint32_t a, void *p, size_t n, bool write)
{
    static unsigned failures;
    if (a >= 0x20000000u || n > 0x20000000u - a) {
        if(failures++<32)fprintf(stderr,"SMEG software GL RAM range rejected address=%08x bytes=%zu write=%d\n",a,n,write);
        return false;
    }
    /* This machine's native app pointers are the verified identity RAM map.
     * Debug virtual translation can fail when the current software TLB does not
     * contain an otherwise valid application page. The API bridge accesses the
     * same physical RAM as the native GPU/DMA rather than perturbing guest TLBs. */
#ifdef SMEG_SOFT_GLES_TEST
    return cpu_memory_rw_debug(env_cpu(env), a, p, n, write) == 0;
#else
    (void)env;
    MemTxResult result;
    if (api_ram_cached && a < api_ram_cache.len && n <= api_ram_cache.len-a) {
        if (write) {
            result=address_space_write_cached(&api_ram_cache,a,p,n);
            if (result==MEMTX_OK)address_space_cache_invalidate(&api_ram_cache,a,n);
        } else {
            result=address_space_read_cached(&api_ram_cache,a,p,n);
        }
    } else {
        result=write?address_space_write(&address_space_memory,a,
            MEMTXATTRS_UNSPECIFIED,p,n):address_space_read(&address_space_memory,a,
            MEMTXATTRS_UNSPECIFIED,p,n);
    }
    if(result!=MEMTX_OK&&failures++<32)fprintf(stderr,"SMEG software GL RAM transaction failed address=%08x bytes=%zu write=%d result=%u\n",a,n,write,result);
    return result==MEMTX_OK;
#endif
}
static uint32_t word(CPUPPCState *env, unsigned slot)
{
    uint8_t b[4];
    if (slot < 8) { return env->gpr[3 + slot]; }
    if (!guest(env, env->gpr[1] + 8 + 4 * (slot - 8), b, 4, false)) { return 0; }
    return ldl_be_p(b);
}
static double floating(CPUPPCState *env, unsigned reg)
{
    uint64_t bits = *cpu_fpr_ptr(env, reg); double f;
    memcpy(&f, &bits, 8); return f;
}
static bool initialize(SoftGL *s)
{
    if (s->attempted) { return s->ready; }
    s->attempted = true;
    s->trace_timing=getenv("SMEG_TRACE_GL_TIMING")||getenv("SMEG_TRACE_TOUCH");
    const char *renderer=getenv("SMEG_GL_RENDERER");
    if(!renderer||!renderer[0])renderer="auto";
    if(!strcmp(renderer,"software")) {
        /* Explicit software mode selects Mesa where GLVND provides its manifest.
         * Auto mode leaves all caller renderer/vendor preferences untouched. */
        setenv("LIBGL_ALWAYS_SOFTWARE","1",1);
        const char *mesa="/usr/share/glvnd/egl_vendor.d/50_mesa.json";
        FILE *manifest=fopen(mesa,"r");
        if(manifest){fclose(manifest);setenv("__EGL_VENDOR_LIBRARY_FILENAMES",mesa,0);}
    } else if(strcmp(renderer,"auto")) {
        fprintf(stderr,"SMEG host GL: invalid SMEG_GL_RENDERER=%s (expected auto or software)\n",renderer);
        return false;
    }
    setenv("EGL_PLATFORM", "surfaceless", 0);
    PFNEGLGETPLATFORMDISPLAYEXTPROC platform =
        (void *)eglGetProcAddress("eglGetPlatformDisplayEXT");
    s->display = platform ? platform(EGL_PLATFORM_SURFACELESS_MESA,
                         EGL_DEFAULT_DISPLAY, NULL) : eglGetDisplay(EGL_DEFAULT_DISPLAY);
    EGLint major, minor, count; EGLConfig config;
    EGLint attrs[] = {EGL_SURFACE_TYPE,EGL_PBUFFER_BIT,
        EGL_RENDERABLE_TYPE,EGL_OPENGL_BIT,EGL_RED_SIZE,8,EGL_GREEN_SIZE,8,
        EGL_BLUE_SIZE,8,EGL_ALPHA_SIZE,8,EGL_DEPTH_SIZE,24,EGL_STENCIL_SIZE,8,EGL_NONE};
    EGLint size[] = {EGL_WIDTH,800,EGL_HEIGHT,480,EGL_NONE};
    if (!eglInitialize(s->display,&major,&minor) || !eglBindAPI(EGL_OPENGL_API) ||
        !eglChooseConfig(s->display,attrs,&config,1,&count) || count != 1) { goto fail; }
    s->surface = eglCreatePbufferSurface(s->display,config,size);
    s->context = eglCreateContext(s->display,config,EGL_NO_CONTEXT,NULL);
    if (s->surface == EGL_NO_SURFACE || s->context == EGL_NO_CONTEXT ||
        !eglMakeCurrent(s->display,s->surface,s->surface,s->context)) { goto fail; }
    s->unpack = s->pack = 4; s->ready = true;
    fprintf(stderr,"SMEG host GL (%s): %s / %s\n",renderer,glGetString(GL_RENDERER),glGetString(GL_VERSION));
    return true;
fail:
    fprintf(stderr,"SMEG software GL context failed: EGL error %#x\n",eglGetError());
    return false;
}
static const Export *lookup(uint32_t pc)
{
    size_t lo=0,hi=G_N_ELEMENTS(exports);
    if (pc<exports[0].pc||pc>exports[hi-1].pc) return NULL;
    while(lo<hi){
        size_t mid=lo+(hi-lo)/2;
        if(exports[mid].pc==pc)return &exports[mid];
        if(exports[mid].pc<pc)lo=mid+1;else hi=mid;
    }
    return NULL;
}
static const UpgradeAlias *lookup_upgrade(const SoftGL *s, uint32_t pc)
{
    if (!s->upgrade_base || pc < s->upgrade_base) return NULL;
    uint32_t offset = pc - s->upgrade_base;
    /* All173 matched GL exports in the original upgrade_256.out are at
     * upgrade.out offset+0x74. Their masked instruction signatures are checked
     * before dispatch; this does not change the native module or its imports. */
    if (s->bsp256) {
        if (offset < 0x74) return NULL;
        offset -= 0x74;
    }
    size_t lo = 0, hi = G_N_ELEMENTS(upgrade_aliases);
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (upgrade_aliases[mid].offset == offset) return &upgrade_aliases[mid];
        if (upgrade_aliases[mid].offset < offset) lo = mid + 1; else hi = mid;
    }
    return NULL;
}
uint32_t smeg_soft_gles_get_upgrade_base(void)
{
    return active_soft_gl ? active_soft_gl->upgrade_base : 0;
}
bool smeg_soft_gles_set_upgrade_base(uint32_t base)
{
    if (!active_soft_gl || (base && (base < 0x01000000 || base >= 0x1f000000)))
        return false;
    active_soft_gl->upgrade_base = base;
    active_soft_gl->upgrade_calls = 0;
#ifndef SMEG_SOFT_GLES_TEST
    /* Retranslate any API entries that ran before the observed base was set. */
    tb_flush(active_soft_gl_cpu);
#endif
    return true;
}
static const Export *resolve_export(const SoftGL *s, uint32_t pc)
{
    const Export *e = lookup(pc - s->application_delta);
    const UpgradeAlias *a = e ? NULL : lookup_upgrade(s, pc);
    return e ? e : a ? &exports[a->export_index] : NULL;
}
static bool upgrade_signature(CPUPPCState *env, uint32_t pc,
                              const UpgradeAlias *a)
{
    uint8_t code[16];
    if (!guest(env, pc, code, sizeof(code), false)) return false;
    for (unsigned i = 0; i < 4; i++)
        if ((ldl_be_p(code + 4*i) & a->mask[i]) !=
            (a->signature[i] & a->mask[i])) return false;
    return true;
}
static bool scalar_signature(const char *sig)
{
    return sig && !strchr(sig,'p') && strlen(sig)<18;
}
static bool special(const char *n)
{
    static const char *names[] = {"eglSwapBuffers","glGetString","glGenTextures",
        "glDeleteTextures","glGetIntegerv","glGetFloatv","glGetFixedv","glGetBooleanv",
        "glVertexPointer","glColorPointer","glNormalPointer","glTexCoordPointer",
        "glEnableClientState","glDisableClientState","glClientActiveTexture",
        "glDrawArrays","glDrawElements","glTexImage2D","glTexSubImage2D",
        "glReadPixels","glTexImage2DMM","glCompressedTexImage2DMM","glCompressedTexImage2DMMDirect","glGetTexImageMM","glOrthof","glFrustumf","glClearDepthf","glDepthRangef",
        "glLoadMatrixf","glMultMatrixf","glLoadMatrixx","glMultMatrixx"};
    for(size_t i=0;i<G_N_ELEMENTS(names);i++) if(!strcmp(n,names[i])) return true;
    return false;
}
static void *hostfn(const char *n)
{
    void *p=dlsym(RTLD_DEFAULT,n);
    return p ? p : (void *)eglGetProcAddress(n);
}
static const char *fixed_alias(const char *n)
{
    static const char *pairs[][2] = {
        {"glAlphaFuncx","glAlphaFunc"},{"glClearColorx","glClearColor"},
        {"glColor4x","glColor4f"},{"glFogx","glFogf"},
        {"glLightx","glLightf"},{"glLightModelx","glLightModelf"},
        {"glLineWidthx","glLineWidth"},{"glMaterialx","glMaterialf"},
        {"glMultiTexCoord4x","glMultiTexCoord4f"},{"glNormal3x","glNormal3f"},
        {"glPointSizex","glPointSize"},{"glPolygonOffsetx","glPolygonOffset"},
        {"glRotatex","glRotatef"},{"glScalex","glScalef"},
        {"glTexEnvx","glTexEnvf"},{"glTexParameterx","glTexParameterf"},
        {"glTranslatex","glTranslatef"},{"glSampleCoveragex","glSampleCoverage"},
    };
    for(size_t i=0;i<G_N_ELEMENTS(pairs);i++)if(!strcmp(n,pairs[i][0]))return pairs[i][1];
    return NULL;
}

/* Original BSP exports memcpy/memmove through the same bcopy implementation.
 * Accelerate only ordinary application RAM buffers and application callers;
 * kernel/MMIO/boot accesses retain the native instructions and fault behavior. */
static bool memory_entry(uint32_t pc)
{
    return pc == 0x002cb648 || pc == 0x002cb684 ||
           pc == 0x002cb6c0 || pc == 0x002aa15c;
}

static uint32_t memory_pc(const SoftGL *s, uint32_t pc)
{
    if (!s->bsp256) return pc;
    /* Exact exported addresses from the car's matching BSP256 symbol map. */
    switch (pc) {
    case 0x002cb508: return 0x002cb648;
    case 0x002cb544: return 0x002cb684;
    case 0x002cb580: return 0x002cb6c0;
    case 0x002aa038: return 0x002aa15c;
    default: return 0;
    }
}

static bool memory_call(SoftGL *s, CPUPPCState *env, uint32_t pc)
{
    if (env->lr < 0x01000000 ||
        env->lr >= (s->fast_module_memory ? 0x20000000 : 0x03800000)) {
        return false;
    }
    uint32_t dst = env->gpr[3], src = env->gpr[4], n = env->gpr[5];
    bool fill = pc == 0x002cb6c0;
    if (pc == 0x002aa15c) {
        src = env->gpr[3];
        dst = env->gpr[4];
    }
    if (n > 32 * 1024 * 1024 || dst < 0x01000000 ||
        dst >= 0x20000000 || n > 0x20000000 - dst ||
        (!fill && (src < 0x01000000 || src >= 0x20000000 ||
                   n > 0x20000000 - src))) {
        return false;
    }
    g_autofree uint8_t *bytes = g_malloc(n ? n : 1);
    if (fill) {
        memset(bytes, env->gpr[4] & 255, n);
    } else if (!guest(env, src, bytes, n, false)) {
        return false;
    }
    /* Whole-source staging matches original overlap-safe bcopy, including
     * memcpy's native wrapper, and address-space writes retain dirty tracking. */
    if (!guest(env, dst, bytes, n, true)) {
        return false;
    }
    if (pc != 0x002aa15c) {
        env->gpr[3] = dst;
    }
    s->memory_calls++;
    s->memory_bytes+=n;
    env->nip = env->lr;
    return true;
}

static bool match(void *opaque, uint32_t pc)
{
    SoftGL *s = opaque;
    if (s->fast_memory && memory_entry(memory_pc(s,pc))) {
        return true;
    }
    uint32_t native_pc = pc - s->application_delta;
    if(native_pc==0x01dfce0c||native_pc==0x01dfc778||native_pc==0x01dfca58)return true; /* Original Qt MM allocation return. */
    const Export *e=resolve_export(s,pc);
    /* No context creation, mutable cache, or host GL call on translation threads. */
    return e && (special(e->name) || (scalar_signature(e->sig) &&
           !strstr(e->name,"MM") && !strstr(e->name,"DrawTex") &&
           (!strchr(e->sig,'x') || fixed_alias(e->name))));
}
static unsigned components(GLenum pname)
{
    switch(pname) {
    case GL_VIEWPORT: case GL_SCISSOR_BOX: case GL_COLOR_CLEAR_VALUE:
    case GL_CURRENT_COLOR: case GL_CURRENT_TEXTURE_COORDS: return 4;
    case GL_CURRENT_NORMAL: return 3;
    case GL_COMPRESSED_TEXTURE_FORMATS: { GLint n=0;glGetIntegerv(GL_NUM_COMPRESSED_TEXTURE_FORMATS,&n);return n>0&&n<=4096?n:0; }
    case GL_DEPTH_RANGE: case GL_ALIASED_POINT_SIZE_RANGE:
    case GL_ALIASED_LINE_WIDTH_RANGE: case GL_MAX_VIEWPORT_DIMS: return 2;
    case GL_MODELVIEW_MATRIX: case GL_PROJECTION_MATRIX: case GL_TEXTURE_MATRIX:return 16;
    default:return 1;
    }
}
static unsigned bytes_per_type(unsigned type)
{
    switch(type){case GL_BYTE:case GL_UNSIGNED_BYTE:return 1;
    case GL_SHORT:case GL_UNSIGNED_SHORT:return 2;
    case GL_FLOAT:case GL_INT:case GL_UNSIGNED_INT:case 0x140c:return 4;
    default:return 0;}
}
static bool array_data(CPUPPCState *env, Array *a, unsigned count, void **out, GLenum *type)
{
    unsigned unit=bytes_per_type(a->type), width=unit*a->size;
    size_t stride=a->stride?a->stride:width;
    if(!unit || a->size>4 || count>1048576 || stride>1048576 ||
       (uint64_t)count*width>64*1024*1024) return false;
    if(count && (uint64_t)a->address+(count-1)*(uint64_t)stride+width>0x20000000u)return false;
    size_t n=(size_t)count*width; uint8_t *p=g_malloc(n?n:1);
    /* Gather tightly packed or interleaved attributes in bounded bulk reads.
     * Guest memory can change each draw; this deliberately caches no contents. */
    if (count && stride == width) {
        if (!guest(env,a->address,p,n,false)) {g_free(p);return false;}
    } else if (count) {
        size_t batch=MAX((size_t)1,65536 / MAX(stride,(size_t)1));
        size_t capacity=(MIN((size_t)count,batch)-1)*stride+width;
        uint8_t *raw=g_malloc(capacity);
        for(unsigned i=0;i<count;) {
            size_t amount=MIN((size_t)count-i,batch);
            size_t span=(amount-1)*stride+width;
            if (!guest(env,a->address+(uint64_t)i*stride,raw,span,false)) {
                g_free(raw);g_free(p);return false;
            }
            for(size_t j=0;j<amount;j++)memcpy(p+((size_t)i+j)*width,raw+j*stride,width);
            i+=amount;
        }
        g_free(raw);
    }
    for(size_t i=0;i<n;i+=unit) {
        if(unit==2){uint16_t v=lduw_be_p(p+i);memcpy(p+i,&v,2);}
        if(unit==4){uint32_t v=ldl_be_p(p+i);memcpy(p+i,&v,4);}
    }
    if(a->type==0x140c) {
        for(size_t i=0;i<n;i+=4){int32_t v;float f;memcpy(&v,p+i,4);f=v/65536.0f;memcpy(p+i,&f,4);}
        *type=GL_FLOAT;
    } else *type=a->type;
    *out=p;return true;
}
static bool upload_native_textures(CPUPPCState *env,SoftGL *s)
{
    bool pending=false;
    for(unsigned i=0;i<s->native_count;i++)if(!s->native_textures[i].uploaded){pending=true;break;}
    if(!pending)return true;
    GLint binding;glGetIntegerv(GL_TEXTURE_BINDING_2D,&binding);
    for(unsigned i=0;i<s->native_count;i++) {
        NativeTexture*t=&s->native_textures[i];
        if(t->uploaded)continue;
        if(!t->cpu){fprintf(stderr,"SMEG software GL native texture pending tex=%u level=%u out=%08x return=%08x entrysp=%08x\n",t->texture,t->level,t->output,t->return_pc,t->entry_sp);return false;}
        uint64_t len=(uint64_t)t->width*t->height*4;
        if(len>64*1024*1024)return false;
        uint8_t*p=g_malloc(len?len:1);
        GLenum format=GL_BGRA;
        if(t->compressed){
            size_t required=(size_t)MAX(t->width,8u)*MAX(t->height,8u)/2;
            if(t->format!=0x8c02||t->image_bytes<required||required>64*1024*1024){g_free(p);return false;}
            uint8_t*raw=g_malloc(required);
            bool valid=guest(env,t->cpu,raw,required,false)&&
                smeg_decode_pvrtc4(raw,t->width,t->height,p);
            g_free(raw);if(!valid){g_free(p);return false;}
            format=GL_RGBA;
            fprintf(stderr,"SMEG software GL decoded actual PVRTC texture%u level%u %ux%u source=%08x bytes=%zu\n",t->texture,t->level,t->width,t->height,t->cpu,required);
        }else if(!guest(env,t->cpu,p,len,false)){g_free(p);return false;}
        /* Qt01dfce70..88 byte-swaps ARGB32 before its STW: already BGRA bytes. */
        glBindTexture(t->target,t->texture);
        glPixelStorei(GL_UNPACK_ALIGNMENT,1);
        glTexImage2D(t->target,t->level,GL_RGBA,t->width,t->height,0,
                     format,GL_UNSIGNED_BYTE,p);
        glPixelStorei(GL_UNPACK_ALIGNMENT,s->unpack);
        g_free(p);t->uploaded=true;
    }
    glBindTexture(GL_TEXTURE_2D,binding);return true;
}
static void trace_error(SoftGL*s,const char*where)
{
    GLenum err=glGetError();
    if(err!=GL_NO_ERROR){if(!s->pending_error)s->pending_error=err;
        fprintf(stderr,"SMEG software GL host error %s=%#x\n",where,err);}
}
static void trace_draw(SoftGL*s,GLenum mode,unsigned first,unsigned count,void*vertices,GLenum vertex_type)
{
    s->draws++;
    if(s->draws>32)return;
    GLint viewport[4],scissor[4],buffer,active,tex;GLfloat color[4],model[16],projection[16];
    glGetIntegerv(GL_VIEWPORT,viewport);glGetIntegerv(GL_SCISSOR_BOX,scissor);
    glGetIntegerv(GL_ARRAY_BUFFER_BINDING,&buffer);glGetIntegerv(GL_ACTIVE_TEXTURE,&active);
    glGetIntegerv(GL_TEXTURE_BINDING_2D,&tex);glGetFloatv(GL_CURRENT_COLOR,color);
    glGetFloatv(GL_MODELVIEW_MATRIX,model);glGetFloatv(GL_PROJECTION_MATRIX,projection);
    fprintf(stderr,"SMEG software GL draw%u mode=%#x first=%u count=%u vertex=%08x,size%u,type%#x,stride%u,colorarray=%d texarray=%d active=%#x texture=%d enabled=%d VBO=%d blend=%d scissor=%d(%d,%d,%d,%d) viewport=%d,%d,%d,%d color=%g,%g,%g,%g model=%g,%g,%g,%g,%g,%g proj=%g,%g,%g,%g,%g,%g\n",
        s->draws,mode,first,count,s->vertex.address,s->vertex.size,s->vertex.type,s->vertex.stride,
        s->color.enabled,s->tex[s->client_texture].enabled,active,tex,glIsEnabled(GL_TEXTURE_2D),buffer,
        glIsEnabled(GL_BLEND),glIsEnabled(GL_SCISSOR_TEST),scissor[0],scissor[1],scissor[2],scissor[3],
        viewport[0],viewport[1],viewport[2],viewport[3],color[0],color[1],color[2],color[3],
        model[0],model[5],model[10],model[12],model[13],model[15],
        projection[0],projection[5],projection[10],projection[12],projection[13],projection[15]);
    if(vertices&&vertex_type==GL_FLOAT){float*v=vertices;
        unsigned n=MIN(12u,(first+count)*s->vertex.size);
        fprintf(stderr,"SMEG software GL vertexsamples");for(unsigned i=0;i<n;i++)fprintf(stderr," %g",v[i]);fputc('\n',stderr);}
}
static bool draw(CPUPPCState *env,SoftGL *s,GLenum mode,unsigned first,unsigned count,
                 GLenum index_type,uint32_t index_addr)
{
    if(s->trace_timing) {
        if(!s->frame_first_draw_ns)s->frame_first_draw_ns=host_time_ns();
        s->frame_draws++;
    }
    if(!upload_native_textures(env,s))return false;
    uint8_t *indices=NULL;unsigned max=first+count;
    if(count>1048576 || max<first) return false;
    if(index_addr) {
        unsigned size=index_type==GL_UNSIGNED_BYTE?1:index_type==GL_UNSIGNED_SHORT?2:0;
        if(!size) return false;
        indices=g_malloc((size_t)count*size);max=0;
        if(!guest(env,index_addr,indices,(size_t)count*size,false)) goto fail;
        for(unsigned i=0;i<count;i++) {
            unsigned v=size==1?indices[i]:lduw_be_p(indices+i*2);
            if(size==2){uint16_t x=v;memcpy(indices+i*2,&x,2);}
            max=MAX(max,v+1);
        }
    }
    Array *arrays[]={&s->vertex,&s->color,&s->normal,&s->tex[0],&s->tex[1],&s->tex[2],&s->tex[3]};
    void *data[7]={0};GLenum type=0,vertex_type=0;
    for(unsigned i=0;i<7;i++) {
        if(!arrays[i]->enabled) continue;
        if(!array_data(env,arrays[i],max,&data[i],&type)) {
            for(unsigned j=0;j<7;j++)g_free(data[j]);
            goto fail;
        }
        if(i==0){glVertexPointer(arrays[i]->size,type,0,data[i]);vertex_type=type;}
        else if(i==1)glColorPointer(arrays[i]->size,type,0,data[i]);
        else if(i==2)glNormalPointer(type,0,data[i]);
        else{glClientActiveTexture(GL_TEXTURE0+i-3);glTexCoordPointer(arrays[i]->size,type,0,data[i]);}
    }
    glClientActiveTexture(GL_TEXTURE0+s->client_texture);
    trace_draw(s,mode,first,count,data[0],vertex_type);
    if(indices)glDrawElements(mode,count,index_type,indices);else glDrawArrays(mode,first,count);
    if(s->draws<=32)trace_error(s,"draw");
    /* Client pointers must not dangle after the call. */
    for(unsigned i=0;i<7;i++)g_free(data[i]);
    g_free(indices);return true;
fail:g_free(indices);return false;
}
static unsigned pixel_width(unsigned format,unsigned type)
{
    if(type==GL_UNSIGNED_SHORT_5_6_5||type==GL_UNSIGNED_SHORT_4_4_4_4||type==GL_UNSIGNED_SHORT_5_5_5_1)return 2;
    if(type!=GL_UNSIGNED_BYTE)return 0;
    switch(format){case GL_RGBA:return 4;case GL_RGB:return 3;case GL_LUMINANCE_ALPHA:return 2;
    case GL_ALPHA:case GL_LUMINANCE:return 1;default:return 0;}
}
static bool pixels(CPUPPCState *env,SoftGL *s,const char*n,uint32_t *a)
{
    bool sub=!strcmp(n,"glTexSubImage2D"), read=!strcmp(n,"glReadPixels");
    unsigned w=read?a[2]:a[sub?4:3],h=read?a[3]:a[sub?5:4];
    unsigned fmt=read?a[4]:a[sub?6:6],type=read?a[5]:a[sub?7:7];
    uint32_t addr=read?a[6]:a[8]; unsigned unit=pixel_width(fmt,type);
    unsigned align=read?s->pack:s->unpack;
    if(!unit||w>16384||h>16384||!align)return false;
    uint64_t pitch=((uint64_t)w*unit+align-1)&~(uint64_t)(align-1),len=pitch*h;
    if(len>64*1024*1024)return false;
    uint8_t *p=addr?g_malloc0(MAX(len,1)):NULL;
    if(p&&!read&&!guest(env,addr,p,len,false)){g_free(p);return false;}
    if(p&&!read&&type!=GL_UNSIGNED_BYTE)for(unsigned y=0;y<h;y++)for(unsigned x=0;x<w;x++){
        uint16_t v=lduw_be_p(p+y*pitch+x*2);memcpy(p+y*pitch+x*2,&v,2);}
    if(read){if(!p)return false;glReadPixels(a[0],a[1],w,h,fmt,type,p);}
    else if(sub)glTexSubImage2D(a[0],a[1],a[2],a[3],w,h,fmt,type,p);
    else glTexImage2D(a[0],a[1],a[2],w,h,a[5],fmt,type,p);
    if(read&&type!=GL_UNSIGNED_BYTE)for(unsigned y=0;y<h;y++)for(unsigned x=0;x<w;x++){
        uint16_t v;memcpy(&v,p+y*pitch+x*2,2);stw_be_p(p+y*pitch+x*2,v);}
    bool ok=!read||guest(env,addr,p,len,true);g_free(p);return ok;
}
static bool swap(CPUPPCState *env,SoftGL*s)
{
    uint32_t fb=s->framebuffer?s->framebuffer(s->fbopaque):0;
    if(!fb)return false;
    int64_t begin_ns=s->trace_timing?host_time_ns():0;
    const size_t pitch=800*4, bytes=pitch*480;
    if (!s->swap_pixels) {
        s->swap_pixels=g_malloc(bytes);s->swap_flipped=g_malloc(bytes);
    }
    uint8_t *bgra=s->swap_pixels;
    /* glReadPixels synchronizes preceding rendering. BGRA matches the native
     * DIU byte layout directly; only vertical row order needs conversion. */
    glPixelStorei(GL_PACK_ALIGNMENT,1);
    glReadPixels(0,0,800,480,GL_BGRA,GL_UNSIGNED_BYTE,bgra);
    int64_t read_ns=s->trace_timing?host_time_ns():0;
    if(s->swaps++<16){unsigned nonwhite=0,nonzero=0;for(unsigned i=0;i<800*480;i++){if(bgra[4*i]!=255||bgra[4*i+1]!=255||bgra[4*i+2]!=255)nonwhite++;if(bgra[4*i]||bgra[4*i+1]||bgra[4*i+2])nonzero++;}
        fprintf(stderr,"SMEG software GL swap%u fb=%08x draws=%u nonwhite=%u nonblack=%u centerRGBA=%u,%u,%u,%u\n",s->swaps,fb,s->draws,nonwhite,nonzero,bgra[(240*800+400)*4+2],bgra[(240*800+400)*4+1],bgra[(240*800+400)*4],bgra[(240*800+400)*4+3]);trace_error(s,"swap");}
    for(unsigned y=0;y<480;y++)memcpy(s->swap_flipped+y*pitch,bgra+(479-y)*pitch,pitch);
    bool ok=guest(env,fb,s->swap_flipped,bytes,true);
    if (ok && s->present) {
        s->present(s->fbopaque);
    }
    glPixelStorei(GL_PACK_ALIGNMENT,s->pack);
    if(s->trace_timing) {
        int64_t end_ns=host_time_ns();
        fprintf(stderr,"SMEG GL commit swap=%u fb=%08x first_draw_ns=%" PRId64
                " begin_ns=%" PRId64 " read_ns=%" PRId64 " host_ns=%" PRId64
                " draws=%u read_us=%" PRId64 " copy_us=%" PRId64 " ok=%u"
                " mem_calls=%" PRIu64 " mem_bytes=%" PRIu64 "\n",
                s->swaps,fb,s->frame_first_draw_ns,begin_ns,read_ns,end_ns,
                s->frame_draws,(read_ns-begin_ns)/1000,(end_ns-read_ns)/1000,ok,
                s->memory_calls,s->memory_bytes);
        s->frame_first_draw_ns=0;s->frame_draws=0;
    }
    return ok;
}
static bool call(void *opaque,CPUPPCState *env,uint32_t pc)
{
    SoftGL*s=opaque;
    if (s->fast_memory && memory_entry(memory_pc(s,pc))) {
        return memory_call(s, env, memory_pc(s,pc));
    }
    uint32_t native_pc = pc - s->application_delta;
    if(native_pc==0x01dfce0c||native_pc==0x01dfc778||native_pc==0x01dfca58) {
        for(unsigned i=s->native_count;i>0;i--){NativeTexture*t=&s->native_textures[i-1];
            if(t->return_pc==pc&&t->entry_sp==env->gpr[1]&&!t->cpu){
                uint8_t b[4];if(guest(env,t->output,b,4,false))t->cpu=ldl_be_p(b);
                break;
            }
        }
        return false; /* Continue the original Qt CPU copy instruction. */
    }
    const UpgradeAlias *upgrade_alias=lookup_upgrade(s,pc);
    if(upgrade_alias&&!upgrade_signature(env,pc,upgrade_alias))return false;
    if(upgrade_alias && s->upgrade_calls++<8)
        fprintf(stderr,"SMEG updater GL %s at%08x verified instruction signature\n",exports[upgrade_alias->export_index].name,pc);
    const Export*e=resolve_export(s,pc);if(!e||!initialize(s))return false;
    const char*n=e->name;uint32_t a[16]={0};unsigned integer_count=0;
    for(const char *t=e->sig+1;*t;t++)if(*t!='f')integer_count++;
    for(unsigned i=0;i<integer_count&&i<G_N_ELEMENTS(a);i++)a[i]=word(env,i);
    if(s->calls++<256)fprintf(stderr,"SMEG software GL call%u %s args=%08x,%08x,%08x,%08x float=%g,%g,%g,%g\n",s->calls,n,a[0],a[1],a[2],a[3],floating(env,1),floating(env,2),floating(env,3),floating(env,4));
    bool ok=true;uint32_t ret=0;
    if(!strcmp(n,"glGetError")){ret=s->pending_error?s->pending_error:glGetError();s->pending_error=0;}
    else if(!strcmp(n,"glCompressedTexImage2DMM")||!strcmp(n,"glCompressedTexImage2DMMDirect")) {
        bool direct=!strcmp(n,"glCompressedTexImage2DMMDirect");
        unsigned level=direct?0:a[1],format=a[direct?1:2];
        if(format!=0x8c02||s->native_count>=G_N_ELEMENTS(s->native_textures))return false;
        GLint binding;glGetIntegerv(GL_TEXTURE_BINDING_2D,&binding);NativeTexture*t=NULL;
        for(unsigned i=0;i<s->native_count;i++)if(s->native_textures[i].texture==(uint32_t)binding&&s->native_textures[i].level==level){t=&s->native_textures[i];break;}
        if(!t)t=&s->native_textures[s->native_count++];
        *t=(NativeTexture){.texture=binding,.target=a[0],.level=level,
            .format=format,.width=a[direct?2:3],.height=a[direct?3:4],
            .image_bytes=a[direct?5:6],.output=a[direct?6:7],.compressed=true,
            .return_pc=env->lr,.entry_sp=env->gpr[1]};
        return false; /* Original driver allocates actual writable PB memory. */
    }
    else if(!strcmp(n,"glTexImage2DMM")) {
        /* Preserve original allocator and all original texture metadata. */
        if(s->native_count>=G_N_ELEMENTS(s->native_textures)||a[6]!=GL_BGRA||
           a[7]!=GL_UNSIGNED_BYTE||a[2]!=GL_BGRA||a[5]!=0)return false;
        GLint binding;glGetIntegerv(GL_TEXTURE_BINDING_2D,&binding);
        NativeTexture*t=NULL;
        for(unsigned i=0;i<s->native_count;i++)if(s->native_textures[i].texture==(uint32_t)binding&&s->native_textures[i].level==a[1]){t=&s->native_textures[i];break;}
        if(!t)t=&s->native_textures[s->native_count++];
        *t=(NativeTexture){.texture=binding,.target=a[0],.level=a[1],.width=a[3],
            .height=a[4],.format=a[6],.type=a[7],.output=a[8],
            .return_pc=env->lr,.entry_sp=env->gpr[1]};
        return false;
    } else if(!strcmp(n,"glGetTexImageMM")) {
        if(!upload_native_textures(env,s))return false;
        GLint w,h;glGetTexLevelParameteriv(a[0],a[1],GL_TEXTURE_WIDTH,&w);
        glGetTexLevelParameteriv(a[0],a[1],GL_TEXTURE_HEIGHT,&h);
        unsigned unit=pixel_width(a[2],a[3]);
        if(w<0||h<0||!unit||(uint64_t)w*h*unit>64*1024*1024)return false;
        size_t pitch=((size_t)w*unit+s->pack-1)&~(size_t)(s->pack-1),len=pitch*h;
        uint8_t*p=g_malloc0(MAX(len,1));glGetTexImage(a[0],a[1],a[2],a[3],p);
        ok=guest(env,a[4],p,len,true);g_free(p);
    } else if(!strcmp(n,"eglSwapBuffers")){ok=upload_native_textures(env,s)&&swap(env,s);ret=ok;}
    else if(!strcmp(n,"glGetString")){
        /* Preserve native GLES1/PVR capability strings and their lifetime.
         * Desktop Mesa advertises APIs beyond this GLES1 bridge; returning
         * those extensions would incorrectly change native Qt feature paths. */
        return false;
    } else if(!strcmp(n,"glGenTextures")||!strcmp(n,"glDeleteTextures")){
        if(!strcmp(n,"glGenTextures"))return false; /* Native allocation/state. */
        if(a[0]>1048576)return false;
        GLuint*p=g_new(GLuint,a[0]);
        if(n[2]=='G'){glGenTextures(a[0],p);for(unsigned i=0;i<a[0];i++){uint8_t b[4];stl_be_p(b,p[i]);if(!guest(env,a[1]+4*i,b,4,true))ok=false;}}
        else{for(unsigned i=0;i<a[0];i++){uint8_t b[4];if(!guest(env,a[1]+4*i,b,4,false)){ok=false;break;}p[i]=ldl_be_p(b);}if(ok)glDeleteTextures(a[0],p);}g_free(p);
        return false; /* Native glDeleteTextures also frees original objects. */
    } else if(!strncmp(n,"glGet",5)&&strchr(e->sig,'p')){
        unsigned count=components(a[0]);GLint iv[4096];GLfloat fv[4096];GLboolean bv[4096];uint8_t out[16384];
        if(!count || count>4096)return false;
        if(!strcmp(n,"glGetFloatv")){glGetFloatv(a[0],fv);for(unsigned i=0;i<count;i++){uint32_t b;memcpy(&b,&fv[i],4);stl_be_p(out+4*i,b);}}
        else if(!strcmp(n,"glGetBooleanv")){glGetBooleanv(a[0],bv);memcpy(out,bv,count);}
        else if(!strcmp(n,"glGetFixedv")){glGetFloatv(a[0],fv);for(unsigned i=0;i<count;i++)stl_be_p(out+4*i,(int32_t)(fv[i]*65536.0f));}
        else{glGetIntegerv(a[0],iv);for(unsigned i=0;i<count;i++)stl_be_p(out+4*i,iv[i]);}
        ok=guest(env,a[1],out,count*(!strcmp(n,"glGetBooleanv")?1:4),true);
    } else if(strstr(n,"Pointer")){
        Array*p=!strcmp(n,"glVertexPointer")?&s->vertex:!strcmp(n,"glColorPointer")?&s->color:!strcmp(n,"glNormalPointer")?&s->normal:&s->tex[s->client_texture];
        bool normal=p==&s->normal;p->size=normal?3:a[0];p->type=a[normal?0:1];p->stride=a[normal?1:2];p->address=a[normal?2:3];
    } else if(!strcmp(n,"glEnableClientState")||!strcmp(n,"glDisableClientState")){
        Array*p=a[0]==GL_VERTEX_ARRAY?&s->vertex:a[0]==GL_COLOR_ARRAY?&s->color:a[0]==GL_NORMAL_ARRAY?&s->normal:a[0]==GL_TEXTURE_COORD_ARRAY?&s->tex[s->client_texture]:NULL;
        if(!p)return false;
        p->enabled=!strcmp(n,"glEnableClientState");if(p->enabled)glEnableClientState(a[0]);else glDisableClientState(a[0]);
    } else if(!strcmp(n,"glClientActiveTexture")){if(a[0]<GL_TEXTURE0||a[0]>=GL_TEXTURE0+4)return false;s->client_texture=a[0]-GL_TEXTURE0;glClientActiveTexture(a[0]);}
    else if(!strcmp(n,"glDrawArrays"))ok=draw(env,s,a[0],a[1],a[2],0,0);
    else if(!strcmp(n,"glDrawElements"))ok=draw(env,s,a[0],0,a[1],a[2],a[3]);
    else if(!strcmp(n,"glTexImage2D")||!strcmp(n,"glTexSubImage2D")||!strcmp(n,"glReadPixels"))ok=pixels(env,s,n,a);
    else if(!strcmp(n,"glOrthof")||!strcmp(n,"glFrustumf")){double f[6];for(unsigned i=0;i<6;i++)f[i]=floating(env,i+1);if(n[2]=='O')glOrtho(f[0],f[1],f[2],f[3],f[4],f[5]);else glFrustum(f[0],f[1],f[2],f[3],f[4],f[5]);}
    else if(!strcmp(n,"glClearDepthf"))glClearDepth(floating(env,1));
    else if(!strcmp(n,"glDepthRangef"))glDepthRange(floating(env,1),floating(env,2));
    else if(!strncmp(n,"glLoadMatrix",12)||!strncmp(n,"glMultMatrix",12)){
        uint8_t b[64];GLfloat f[16];if(!guest(env,a[0],b,64,false))return false;
        for(unsigned i=0;i<16;i++){uint32_t v=ldl_be_p(b+4*i);if(n[strlen(n)-1]=='x')f[i]=(int32_t)v/65536.0f;else memcpy(&f[i],&v,4);}
        if(strstr(n,"Load"))glLoadMatrixf(f);else glMultMatrixf(f);
    } else if(!strcmp(n,"glTexParameterx") &&
              (a[1]==GL_TEXTURE_MIN_FILTER||a[1]==GL_TEXTURE_MAG_FILTER||
               a[1]==GL_TEXTURE_WRAP_S||a[1]==GL_TEXTURE_WRAP_T||a[1]==GL_GENERATE_MIPMAP)) {
        glTexParameteri(a[0],a[1],a[2]);
    } else if(!strcmp(n,"glTexEnvx") && a[1]!=GL_RGB_SCALE && a[1]!=GL_ALPHA_SCALE) {
        glTexEnvi(a[0],a[1],a[2]);
    } else if(!strcmp(n,"glFogx") && a[0]==GL_FOG_MODE) {
        glFogi(a[0],a[1]);
    } else if(!strcmp(n,"glLightModelx") &&
              (a[0]==GL_LIGHT_MODEL_TWO_SIDE||a[0]==GL_LIGHT_MODEL_LOCAL_VIEWER)) {
        glLightModeli(a[0],a[1]);
    } else {
        union {uint32_t u;int32_t i;float f;double d;} vals[16],result={0};
        void*args[16];unsigned g=0,f=1,count=0;const char*sig=e->sig;
        ScalarCall *cached=&s->scalar_calls[e-exports];
        if(!scalar_signature(sig))return false;
        if(!cached->prepared) {
            const char *alias=fixed_alias(n);
            cached->function=hostfn(alias?alias:n);
            if(!cached->function)return false;
            unsigned argc=0;
            for(const char*t=sig+1;*t;t++,argc++)cached->types[argc]=
                (*t=='f'||*t=='x')?&ffi_type_float:*t=='i'?&ffi_type_sint32:&ffi_type_uint32;
            ffi_type *rtype=*sig=='v'?&ffi_type_void:*sig=='f'?&ffi_type_float:&ffi_type_uint32;
            if(ffi_prep_cif(&cached->cif,FFI_DEFAULT_ABI,argc,rtype,cached->types)!=FFI_OK)return false;
            cached->prepared=true;
        }
        for(const char*t=sig+1;*t;t++,count++){
            args[count]=&vals[count];
            if(*t=='f'){vals[count].f=floating(env,f++);}
            else if(*t=='x'){vals[count].f=(int32_t)a[g++]/65536.0f;}
            else{vals[count].u=a[g++];}
        }
        ffi_call(&cached->cif,FFI_FN(cached->function),&result,args);ret=result.u;if(!strncmp(n,"glIs",4))ret&=255;
        if(*sig=='f'){double v=result.f;uint64_t bits;memcpy(&bits,&v,8);*cpu_fpr_ptr(env,1)=bits;}
        if(!strcmp(n,"glBindTexture")||!strcmp(n,"glActiveTexture"))return false; /* Mirror original texture metadata/unit too. */
        if(!strcmp(n,"glPixelStorei")){if(a[0]==GL_UNPACK_ALIGNMENT)s->unpack=a[1];if(a[0]==GL_PACK_ALIGNMENT)s->pack=a[1];}
    }
    if(!ok){if(s->unsupported++<32)fprintf(stderr,"SMEG software GL could not marshal %s at%08x args=%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x stackarg=%08x\n",n,pc,a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8]);return false;}
    env->gpr[3]=ret;env->nip=env->lr;return true;
}
void smeg_soft_gles_install(CPUPPCState*env,uint32_t(*fb)(void*),
                           void(*present)(void*),void*opaque)
{
#ifndef SMEG_SOFT_GLES_TEST
    /* QEMU's RAM cache preserves code invalidation/dirty tracking on writes;
     * the machine's static identity RAM occupies [0,512MiB), never MMIO. */
    if (!api_ram_cached) {
        int64_t bytes=address_space_cache_init(&api_ram_cache,
                            &address_space_memory,0,0x20000000,true);
        api_ram_cached=bytes>0;
    }
#endif
    SoftGL*s=g_new0(SoftGL,1);s->framebuffer=fb;s->fbopaque=opaque;
    active_soft_gl=s;
#ifndef SMEG_SOFT_GLES_TEST
    active_soft_gl_cpu=env_cpu(env);
#endif
    s->present=present;
    s->bsp256 = g_strcmp0(g_getenv("SMEG_BSP_VARIANT"), "256") == 0;
    s->fast_module_memory = g_strcmp0(g_getenv("SMEG_FAST_MODULE_MEM"), "1") == 0;
    if (g_strcmp0(g_getenv("SMEG_APP_VARIANT"), "audio_bt") == 0) {
        /* All177 intercepted exports match AUDIO_BT/_256 symbol maps at
         * NAV address-0x158; firmware instructions remain unchanged. */
        s->application_delta = -0x158;
    }
    const char *base=g_getenv("SMEG_UPGRADE_GL_BASE");
    if (base && *base) {
        char *end=NULL;
        uint64_t value=g_ascii_strtoull(base,&end,0);
        if (end && !*end && value>=0x01000000 && value<0x1f000000)
            s->upgrade_base=value;
        else fprintf(stderr,"SMEG ignored invalid updater GL base\n");
    }
    s->fast_memory=g_strcmp0(g_getenv("SMEG_FAST_MEM"),"1")==0;
    smeg_soft_gles_register(env,match,call,s);
}
