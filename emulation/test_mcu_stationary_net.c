#include <assert.h>
#include <stdio.h>
#include "emulation/smeg_mcu_peer.h"
int main(void)
{
    const uint8_t identity[4]={5,3,9,1};SmegMcuPeer s;uint8_t tx[92],rx[92];
    const uint8_t speed[8]={0,0,0,0,0,0,0,0x80};
    const uint8_t availability[7]={0,4,0,0,0,0,0};
    const uint8_t info_config[5]={0xa0,0,0,0,0};
    const uint8_t eco[5]={0,0,0,0x80,0},parking[8]={0x90,0xb0,0x15,0xfc,0xfc,0xae,0xc2,0};
    const uint8_t traction[6]={0,0,0,0,2,0};
    smeg_mcu_peer_init(&s,identity);
    assert(!smeg_mcu_peer_net(&s,0x15,speed,7));
    assert(!smeg_mcu_peer_net(&s,0x0f,availability,6));
    assert(!smeg_mcu_peer_net(&s,0x0f,availability,8));
    assert(smeg_mcu_peer_net(&s,0x1a,eco,5));
    assert(smeg_mcu_peer_net(&s,5,parking,8));
    assert(smeg_mcu_peer_net(&s,0x0c,traction,6));
    assert(smeg_mcu_peer_net(&s,0x15,speed,8));
    assert(smeg_mcu_peer_net(&s,0x0f,availability,7));
    assert(smeg_mcu_peer_net(&s,0x0e,info_config,5));
    assert(s.net_count==6);
    for(unsigned i=0;i<100;i++){
        assert(smeg_mcu_peer_net(&s,0x15,speed,8));
        assert(smeg_mcu_peer_net(&s,0x0f,availability,7));
        assert(smeg_mcu_peer_net(&s,0x0e,info_config,5));
    }
    assert(s.net_count==6); /* No starvation/eviction of any other state. */
    memset(tx,255,92);tx[0]=0xaa;tx[1]=0;smeg_mcu_seal(tx,90);
    const uint8_t ids[]={0x1a,5,0x0c,0x15,0x0f,0x0e};
    const uint8_t lengths[]={5,8,6,8,7,5};
    const uint8_t *payloads[]={eco,parking,traction,speed,availability,info_config};
    for(unsigned i=0;i<6;i++){
        assert(smeg_mcu_peer_exchange(&s,tx,rx));
        assert(rx[0]==0x99&&rx[1]==1&&rx[2]==2&&rx[3]==ids[i]&&rx[4]==lengths[i]);
        assert(!memcmp(rx+5,payloads[i],lengths[i]));
        assert(smeg_mcu_crc_valid(rx+2,lengths[i]+3)&&smeg_mcu_crc_valid(rx,90));
    }
    assert(!s.net_count);
    /* Verify captured payload fields used by the original decoder, without
     * replacing its native validity/availability decision with an MMIO flag. */
    unsigned raw=(speed[2]<<8)|speed[3];
    assert(raw==0&&raw!=0xffff&&(speed[7]&0x80));
    assert(((availability[1]>>2)&1)==1);
    puts("Native stationary/dispo/config NET fixtures: IDs, lengths, payloads, CRC and six-state coalescing passed");
}
