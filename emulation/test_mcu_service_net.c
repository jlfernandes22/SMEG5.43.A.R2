#include <assert.h>
#include <stdio.h>
#include "emulation/smeg_mcu_peer.h"
static void frame(uint8_t rx[92]) { memset(rx,255,92);rx[0]=0x99;rx[1]=0;smeg_mcu_seal(rx,90); }
int main(void) {
    const uint8_t identity[4]={5,3,9,1};
    /* Explicit sandbox principal-service raw1; no physical ignition claim. */
    const uint8_t awake[8]={8,0,0,0,0,0,0,0},other[8]={16,1,2,3,4,5,6,7};
    const uint8_t ids[]={0x1a,5,0x0c,0x15,0x0f,0x0e,0x0b,0x22,2};
    const unsigned lens[]={5,8,6,8,7,5,8,5,8};
    SmegMcuPeer s;uint8_t rx[92],before[92];smeg_mcu_peer_init(&s,identity);
    for(unsigned n=0;n<10;n++)if(n!=8)assert(!smeg_mcu_peer_net(&s,2,awake,n));
    assert(!smeg_mcu_peer_net(&s,2,NULL,8));assert(!smeg_mcu_peer_net(&s,3,awake,8));
    assert(smeg_mcu_peer_net(&s,2,awake,8));frame(rx);rx[91]^=1;memcpy(before,rx,92);
    assert(!smeg_mcu_peer_net_pending(&s,rx));assert(s.net_count==1&&!memcmp(before,rx,92));
    assert(smeg_mcu_peer_net(&s,2,other,8));assert(s.net_count==1);
    frame(rx);assert(smeg_mcu_peer_net_pending(&s,rx));
    assert(rx[2]==2&&rx[3]==2&&rx[4]==8&&!memcmp(rx+5,other,8));
    assert(smeg_mcu_crc_valid(rx+2,11)&&smeg_mcu_crc_valid(rx,90));
    for(unsigned round=0;round<30;round++) {
        for(unsigned i=0;i<9;i++)assert(smeg_mcu_peer_net(&s,ids[i],other,lens[i]));
        for(unsigned i=0;i<30;i++)assert(smeg_mcu_peer_net(&s,2,awake,8));
        assert(s.net_count==9);
        for(unsigned i=0;i<9;i++) {frame(rx);assert(smeg_mcu_peer_net_pending(&s,rx));
            assert(rx[1]==1&&rx[2]==2&&rx[3]==ids[i]&&rx[4]==lens[i]);
            assert(!memcmp(rx+5,i==8?awake:other,lens[i]));
            assert(smeg_mcu_crc_valid(rx+2,lens[i]+3)&&smeg_mcu_crc_valid(rx,90));}
        assert(!s.net_count);
    }
    assert(((awake[0]>>3)&3)==1);
    assert(smeg_mcu_peer_net(&s,2,awake,8));uint8_t tx[92]={0xec,0xaa,0x55,0xff,0,0xaa,0x55,0xfb,0x8d};
    assert(smeg_mcu_peer_exchange(&s,tx,rx));assert(!s.net_count&&!s.net_head);
    puts("NET02/8 principal-service: strict bounds, CRC, latest state, nine-ID wrap/order and reset passed");
}
