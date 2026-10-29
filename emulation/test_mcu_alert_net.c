#include <assert.h>
#include <stdio.h>
#include "emulation/smeg_mcu_peer.h"

static void frame(uint8_t rx[92])
{
    memset(rx,255,92);rx[0]=0x99;rx[1]=0;smeg_mcu_seal(rx,90);
}
static void check(uint8_t rx[92], const uint8_t data[8])
{
    assert(rx[0]==0x99&&rx[1]==1&&rx[2]==2&&rx[3]==0x0b&&rx[4]==8);
    assert(!memcmp(rx+5,data,8));
    assert(smeg_mcu_crc_valid(rx+2,11)&&smeg_mcu_crc_valid(rx,90));
}
int main(void)
{
    const uint8_t identity[4]={5,3,9,1};
    const uint8_t eco[8]={2,0x21,1,0,0,0,0,0};
    const uint8_t neutral[8]={0x7f,0xff,0,0,0,0,0,0};
    SmegMcuPeer s;uint8_t rx[92],before[92];
    smeg_mcu_peer_init(&s,identity);
    for(unsigned n=0;n<10;n++)if(n!=8)assert(!smeg_mcu_peer_net(&s,0x0b,eco,n));
    assert(!smeg_mcu_peer_net(&s,0x0b,NULL,8));
    assert(!smeg_mcu_peer_net(&s,0x0a,eco,8));
    assert(smeg_mcu_peer_net(&s,0x0b,eco,8));
    frame(rx);rx[91]^=1;memcpy(before,rx,92);
    assert(!smeg_mcu_peer_net_pending(&s,rx));
    assert(!memcmp(before,rx,92)&&s.net_count==1);
    frame(rx);assert(smeg_mcu_peer_net_pending(&s,rx));check(rx,eco);
    assert(!s.net_count);
    /* Clear is a distinct later publication, after the active event delivered. */
    assert(smeg_mcu_peer_net(&s,0x0b,neutral,8));
    frame(rx);assert(smeg_mcu_peer_net_pending(&s,rx));check(rx,neutral);
    const uint8_t ids[]={0x1a,5,0x0c,0x15,0x0f,0x0e,0x0b};
    const unsigned lengths[]={5,8,6,8,7,5,8};
    const uint8_t payload[8]={1,2,3,4,5,6,7,8};
    for(unsigned round=0;round<10;round++) {
        for(unsigned i=0;i<7;i++)assert(smeg_mcu_peer_net(&s,ids[i],payload,lengths[i]));
        assert(s.net_count==7);
        /* Latest alert state coalesces without evicting the six other IDs. */
        for(unsigned i=0;i<20;i++)assert(smeg_mcu_peer_net(&s,0x0b,eco,8));
        assert(s.net_count==7);
        for(unsigned i=0;i<7;i++) {
            frame(rx);assert(smeg_mcu_peer_net_pending(&s,rx));
            assert(rx[3]==ids[i]&&rx[4]==lengths[i]);
            assert(!memcmp(rx+5,i==6?eco:payload,lengths[i]));
            assert(smeg_mcu_crc_valid(rx+2,lengths[i]+3)&&smeg_mcu_crc_valid(rx,90));
        }
        assert(!s.net_count);
    }
    assert((((eco[0]&0x7f)<<8)|eco[1])==545);
    assert((((neutral[0]&0x7f)<<8)|neutral[1])==0x7fff);
    puts("Native alerts NET0b/8: strict whitelist, CRC, active then clear, seven-ID coalescing/order and ring wrap passed");
}
