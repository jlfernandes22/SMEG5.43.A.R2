#include <assert.h>
#include <stdio.h>
#include "emulation/smeg_mcu_peer.h"
static void empty(uint8_t frame[92])
{memset(frame,255,92);frame[0]=0x99;frame[1]=0;smeg_mcu_seal(frame,90);}
int main(void)
{
    const uint8_t identity[4]={5,3,9,1},health=0x68,economy=0x78;
    SmegMcuPeer peer;uint8_t rx[92];smeg_mcu_peer_init(&peer,identity);
    assert(!smeg_mcu_peer_net(&peer,0x1d,&health,0));
    assert(!smeg_mcu_peer_net(&peer,0x1d,&health,2));
    const uint8_t ids[]={0x1a,5,0xc,0x15,0xf,0xe,0xb,0x22,2,0x13,0x1d};
    const unsigned lens[]={5,8,6,8,7,5,8,5,8,5,1};uint8_t data[8]={0};
    for(unsigned round=0;round<100;round++) {
        for(unsigned i=0;i<11;i++)assert(smeg_mcu_peer_net(&peer,ids[i],data,lens[i]));
        assert(peer.net_count==11);
        assert(smeg_mcu_peer_net(&peer,0x1d,&economy,1));
        assert(smeg_mcu_peer_net(&peer,0x1d,&health,1));
        assert(peer.net_count==11);
        for(unsigned i=0;i<11;i++) {
            empty(rx);assert(smeg_mcu_peer_net_pending(&peer,rx));
            assert(rx[3]==ids[i]&&rx[4]==lens[i]);
            assert(smeg_mcu_crc_valid(rx,90)&&smeg_mcu_crc_valid(rx+2,lens[i]+3));
            if(i==10)assert(rx[5]==health);
        }
    }
    assert(!(health&0x10)&&(health&8));assert((economy&0x10)&&(economy&8));
    puts("Eleven native status IDs coexist; health coalescing, wrap, CRC and explicit economy encoding passed");
}
