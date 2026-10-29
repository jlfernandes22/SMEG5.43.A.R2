#include <assert.h>
#include <stdio.h>
#include "emulation/smeg_mcu_peer.h"

static void frame(uint8_t rx[92])
{
    memset(rx,255,92);rx[0]=0x99;rx[1]=0;smeg_mcu_seal(rx,90);
}
int main(void)
{
    const uint8_t identity[4]={5,3,9,1};
    /* Original enums: AAS LED1 fixed-on means disabled,0 off means enabled.
     * STT LED1 fixed-on indicates ECOoff. These are input fixtures only. */
    const uint8_t disabled[5]={0x40,0,0,4,0};
    const uint8_t enabled[5]={0,0,0,4,0};
    SmegMcuPeer s;uint8_t rx[92],before[92];
    smeg_mcu_peer_init(&s,identity);
    for(unsigned n=0;n<9;n++)if(n!=5)assert(!smeg_mcu_peer_net(&s,0x22,disabled,n));
    assert(!smeg_mcu_peer_net(&s,0x22,NULL,5));
    assert(!smeg_mcu_peer_net(&s,0x23,disabled,5));
    assert(smeg_mcu_peer_net(&s,0x22,disabled,5));
    frame(rx);rx[91]^=1;memcpy(before,rx,92);
    assert(!smeg_mcu_peer_net_pending(&s,rx));
    assert(s.net_count==1&&!memcmp(before,rx,92));
    assert(smeg_mcu_peer_net(&s,0x22,enabled,5));
    assert(s.net_count==1);
    frame(rx);assert(smeg_mcu_peer_net_pending(&s,rx));
    assert(rx[2]==2&&rx[3]==0x22&&rx[4]==5&&!memcmp(rx+5,enabled,5));
    assert(smeg_mcu_crc_valid(rx+2,8)&&smeg_mcu_crc_valid(rx,90));
    /* All eight source-backed inputs coexist; repeated LED updates neither
     * starve the other native observers nor grow a stale-state backlog. */
    const uint8_t ids[]={0x1a,5,0x0c,0x15,0x0f,0x0e,0x0b,0x22};
    const unsigned lengths[]={5,8,6,8,7,5,8,5};
    const uint8_t data[8]={0,1,2,3,4,5,6,7};
    for(unsigned round=0;round<20;round++) {
        for(unsigned i=0;i<8;i++)assert(smeg_mcu_peer_net(&s,ids[i],data,lengths[i]));
        for(unsigned i=0;i<20;i++)assert(smeg_mcu_peer_net(&s,0x22,disabled,5));
        assert(s.net_count==8);
        for(unsigned i=0;i<8;i++) {
            frame(rx);assert(smeg_mcu_peer_net_pending(&s,rx));
            assert(rx[1]==1&&rx[2]==2&&rx[3]==ids[i]&&rx[4]==lengths[i]);
            assert(!memcmp(rx+5,i==7?disabled:data,lengths[i]));
            assert(smeg_mcu_crc_valid(rx+2,lengths[i]+3)&&smeg_mcu_crc_valid(rx,90));
        }
        assert(!s.net_count);
    }
    assert(disabled[0]>>6==1&&enabled[0]>>6==0);
    assert(((disabled[3]>>2)&3)==1&&((enabled[3]>>2)&3)==1);
    assert(smeg_mcu_peer_net(&s,0x22,disabled,5));
    uint8_t tx[92]={0xec,0xaa,0x55,0xff,0,0xaa,0x55,0xfb,0x8d};
    assert(smeg_mcu_peer_exchange(&s,tx,rx));assert(!s.net_count&&!s.net_head);
    puts("Native LED NET22/5: strict size, CRC rejection, exact AAS/STT bytes, latest-state, eight-ID order, wrap and reset passed");
}
