#ifndef TEST_SOFT_GLES_SUPPORT_H
#define TEST_SOFT_GLES_SUPPORT_H
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <assert.h>
typedef struct CPUArchState {uint64_t gpr[32],fpr[32],nip,lr;} CPUPPCState;
static uint8_t test_ram[32*1024*1024];
static unsigned long test_reads, test_writes;
static CPUPPCState *env_cpu(CPUPPCState *e){return e;}
static uint64_t *cpu_fpr_ptr(CPUPPCState*e,int n){return &e->fpr[n];}
static int cpu_memory_rw_debug(CPUPPCState*e,uint32_t a,void*p,size_t n,bool write)
{(void)e;if(write)test_writes++;else test_reads++;if(a>=sizeof(test_ram)||n>sizeof(test_ram)-a)return -1;if(write)memcpy(test_ram+a,p,n);else memcpy(p,test_ram+a,n);return 0;}
static uint16_t lduw_be_p(const void*p){const uint8_t*b=p;return b[0]*256+b[1];}
static uint32_t ldl_be_p(const void*p){const uint8_t*b=p;return ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|(b[2]<<8)|b[3];}
static void stl_be_p(void*p,uint32_t v){uint8_t*b=p;b[0]=v>>24;b[1]=v>>16;b[2]=v>>8;b[3]=v;}
static void stw_be_p(void*p,uint16_t v){uint8_t*b=p;b[0]=v>>8;b[1]=v;}
static void smeg_soft_gles_register(CPUPPCState*e,bool(*m)(void*,uint32_t),bool(*c)(void*,CPUPPCState*,uint32_t),void*o){(void)e;(void)m;(void)c;(void)o;}
void smeg_soft_gles_install(CPUPPCState*,uint32_t(*)(void*),void(*)(void*),void*);
#endif
