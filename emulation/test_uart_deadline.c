/* All UART timing/status/write/drain logic comes from the production board. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define MIN(a,b) ((a)<(b)?(a):(b))
#define QEMU_CLOCK_VIRTUAL 0
struct Timer { bool pending;int64_t deadline; };
typedef struct {
 struct Timer *uart_tx_timer; int64_t uart_tx_deadline_ns;
 uint8_t uart_tx_fifo[4096]; unsigned uart_tx_head,uart_tx_count;
 uint32_t uart_tx_isr;bool psc_tx_enabled[12];unsigned capacity_words,alarm;
 int serial;
} SmegMachineState;
static int64_t now;
static uint8_t output[16384];static unsigned output_count,write_calls,irqs;
static int64_t qemu_clock_get_ns(int clock) { (void)clock;return now; }
static void timer_mod(struct Timer *t,int64_t deadline) {t->pending=true;t->deadline=deadline;}
static void timer_del(struct Timer *t) {t->pending=false;}
static uint32_t smeg_reg_get(SmegMachineState *s,unsigned address,unsigned size)
{assert(size==4);return address==0x1199c?s->capacity_words:s->alarm;}
static void smeg_update_irq(SmegMachineState *s) {(void)s;irqs++;}
static void qemu_chr_fe_write_all(int *sink,const uint8_t *data,unsigned count)
{(void)sink;assert(output_count+count<=sizeof(output));memcpy(output+output_count,data,count);output_count+=count;write_calls++;}
#include "uart_production.inc"
static struct Timer timer;
static SmegMachineState state;
static void reset(unsigned words)
{
 memset(&state,0,sizeof(state));memset(&timer,0,sizeof(timer));
 state.uart_tx_timer=&timer;state.capacity_words=words;state.alarm=2;
 state.psc_tx_enabled[9]=true;now=1000000000;output_count=write_calls=irqs=0;
}
int main(void)
{
 reset(8);int64_t start=now;
 for(unsigned i=0;i<10;i++)smeg_uart_tx_write(&state,'A'+i);
 assert(timer.deadline==start+SMEG_UART_BYTE_NS&&output_count==0);
 now=start+3*SMEG_UART_BYTE_NS+SMEG_UART_BYTE_NS/2;
 smeg_uart_tx_drain(&state);
 assert(output_count==3&&write_calls==1&&!memcmp(output,"ABC",3));
 assert(state.uart_tx_count==7&&timer.deadline==start+4*SMEG_UART_BYTE_NS);
 now=timer.deadline-1;smeg_uart_tx_drain(&state);assert(output_count==3);
 now++;smeg_uart_tx_drain(&state);assert(output_count==4);
 now+=1000000000;smeg_uart_tx_drain(&state);
 assert(output_count==10&&state.uart_tx_count==0&&!timer.pending);
 assert(state.uart_tx_deadline_ns==0&&!memcmp(output,"ABCDEFGHIJ",10));
 assert((state.uart_tx_isr&5)==5); /* intervening alarm and finalempty latched */
 /* A completely idle second gives no credit to a subsequent byte. */
 now+=1000000000;smeg_uart_tx_write(&state,'Z');
 assert(output_count==10&&timer.deadline==now+SMEG_UART_BYTE_NS);
 smeg_uart_tx_drain(&state);assert(output_count==10);
 now+=SMEG_UART_BYTE_NS;smeg_uart_tx_drain(&state);assert(output[10]=='Z');
 /* Late write services elapsed FIFO time before deciding overrun. */
 reset(1);for(unsigned i=0;i<4;i++)smeg_uart_tx_write(&state,i);
 smeg_uart_tx_write(&state,99);assert(state.uart_tx_count==4&&(state.uart_tx_isr&0x10));
 state.uart_tx_isr=0;now+=2*SMEG_UART_BYTE_NS;
 smeg_uart_tx_write(&state,4);assert(output_count==2&&state.uart_tx_count==3);
 assert(!(state.uart_tx_isr&0x10));
 now+=1000000000;smeg_uart_tx_drain(&state);
 assert(output_count==5&&!memcmp(output,(uint8_t[]){0,1,2,3,4},5));
 /* A huge late interval cannot consume beyond the FIFO; ring wraps in order. */
 reset(1);state.uart_tx_head=4094;
 for(unsigned i=0;i<4;i++)smeg_uart_tx_write(&state,10+i);
 now+=1000000000000LL;smeg_uart_tx_drain(&state);
 assert(output_count==4&&!memcmp(output,(uint8_t[]){10,11,12,13},4));
 /* Disable pauses the wire and invalidates its old deadline, retaining bytes. */
 reset(1);smeg_uart_tx_write(&state,42);state.psc_tx_enabled[9]=false;
 now+=1000000000;smeg_uart_tx_drain(&state);
 assert(!output_count&&state.uart_tx_count==1&&!timer.pending&&!state.uart_tx_deadline_ns);
 state.psc_tx_enabled[9]=true;smeg_uart_tx_drain(&state);
 assert(!output_count&&timer.deadline==now+SMEG_UART_BYTE_NS);
 now+=SMEG_UART_BYTE_NS;smeg_uart_tx_drain(&state);assert(output_count==1&&output[0]==42);
 /* A polling guest must see elapsed wire time without a timer callback. */
 reset(8);smeg_uart_tx_write(&state,'P');start=now;
 now=start+SMEG_UART_BYTE_NS-1;smeg_uart_tx_sync(&state);
 assert(output_count==0&&state.uart_tx_count==1);
 now++;smeg_uart_tx_sync(&state);
 assert(output_count==1&&output[0]=='P'&&state.uart_tx_count==0);
 assert(!timer.pending&&!state.uart_tx_deadline_ns);
 /* Polling after a long idle cannot instantly transmit a newly queued byte. */
 now+=1000000000;smeg_uart_tx_write(&state,'Q');smeg_uart_tx_sync(&state);
 assert(output_count==1&&state.uart_tx_count==1);
 now+=SMEG_UART_BYTE_NS;smeg_uart_tx_sync(&state);
 assert(output_count==2&&output[1]=='Q');
 puts("Production UART deadline regression passed: elapsed catch-up, polling synchronization, absolute phase, bounded FIFO/ring, batching, overrun, no idle/disabled credit");
}
