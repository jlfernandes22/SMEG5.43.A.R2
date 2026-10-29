#include <assert.h>
#include <stdio.h>
#include "emulation/smeg_mcu_peer.h"
static void empty(uint8_t *frame,uint8_t type)
{memset(frame,255,92);frame[0]=type;frame[1]=0;smeg_mcu_seal(frame,90);}
static void expect(const uint8_t *rx,uint8_t id,const uint8_t *data,unsigned len)
{
    assert(rx[0]==0x99&&rx[1]==1&&smeg_mcu_crc_valid(rx,90));
    assert(rx[2]==2&&rx[3]==id&&rx[4]==len&&!memcmp(rx+5,data,len));
    assert(smeg_mcu_crc_valid(rx+2,len+3));
}
int main(void)
{
    SmegMcuPeer s;const uint8_t identity[4]={5,3,9,1};
    uint8_t tx[92],rx[92],before[92];
    const uint8_t eco_on[5]={0,0xe8,0,0x40,0},eco_off[5]={0,0xe8,0,0x80,0};
    const uint8_t parking[8]={0x90,0xb0,0x15,0xfc,0xfc,0xae,0xc2,0};
    const uint8_t asr[6]={0,0,0,0,2,0};
    smeg_mcu_peer_init(&s,identity);empty(tx,0xaa);
    assert(!smeg_mcu_peer_net(&s,0x1a,NULL,5));
    assert(!smeg_mcu_peer_net(&s,0x1a,eco_on,4));
    assert(!smeg_mcu_peer_net(&s,5,parking,9));
    assert(!smeg_mcu_peer_net(&s,0x0c,asr,5));
    assert(!smeg_mcu_peer_net(&s,0xff,eco_on,5));
    assert(smeg_mcu_peer_net(&s,0x1a,eco_on,5));
    assert(smeg_mcu_peer_net(&s,5,parking,8));
    assert(smeg_mcu_peer_net(&s,0x0c,asr,6));
    for(unsigned i=0;i<1000;i++)assert(smeg_mcu_peer_net(&s,0x1a,eco_off,5));
    assert(s.net_count==3); /* Coalescing preserves other queued IDs/order. */
    assert(smeg_mcu_peer_exchange(&s,tx,rx));expect(rx,0x1a,eco_off,5);
    assert(smeg_mcu_peer_exchange(&s,tx,rx));expect(rx,5,parking,8);
    assert(smeg_mcu_peer_exchange(&s,tx,rx));expect(rx,0x0c,asr,6);
    assert(s.net_count==0);
    /* Ring wrap and fresh state replacement. */
    for(unsigned i=0;i<20;i++){
        assert(smeg_mcu_peer_net(&s,5,parking,8));
        assert(smeg_mcu_peer_exchange(&s,tx,rx));expect(rx,5,parking,8);
    }
    /* Control ACK and invalid outer CRC must leave both queue/frame intact. */
    assert(smeg_mcu_peer_net(&s,0x1a,eco_on,5));empty(rx,0x6b);
    memcpy(before,rx,92);assert(!smeg_mcu_peer_net_pending(&s,rx));assert(!memcmp(before,rx,92)&&s.net_count==1);
    empty(rx,0x99);rx[91]^=1;memcpy(before,rx,92);
    assert(!smeg_mcu_peer_net_pending(&s,rx));assert(!memcmp(before,rx,92)&&s.net_count==1);
    /* Reject a corrupted inner message even when the outer CRC is valid. */
    empty(rx,0x99);smeg_mcu_append(rx,2,8,2,eco_on,5);rx[5]^=1;smeg_mcu_seal(rx,90);
    memcpy(before,rx,92);assert(!smeg_mcu_peer_net_pending(&s,rx));assert(!memcmp(before,rx,92)&&s.net_count==1);
    /* Never add a second native NET notification to one frame. */
    empty(rx,0x99);smeg_mcu_append(rx,2,2,5,parking,8);smeg_mcu_seal(rx,90);
    memcpy(before,rx,92);assert(!smeg_mcu_peer_net_pending(&s,rx));assert(!memcmp(before,rx,92)&&s.net_count==1);
    /* Boundary fits are checked without dequeue or buffer writes. */
    uint8_t filler[82]={0};empty(rx,0x99);assert(smeg_mcu_append(rx,2,0x40,9,filler,82)==89);smeg_mcu_seal(rx,90);
    memcpy(before,rx,92);assert(!smeg_mcu_peer_net_pending(&s,rx));assert(!memcmp(before,rx,92)&&s.net_count==1);
    /* Touch, key and NET coexist, each keeps its own single-message pace. */
    assert(smeg_mcu_peer_touch(&s,220,675,128,100,0x81));assert(smeg_mcu_peer_key(&s,1,1));
    assert(smeg_mcu_peer_exchange(&s,tx,rx));assert(rx[1]==3&&smeg_mcu_crc_valid(rx,90));
    unsigned out=2;unsigned channels[3]={8,8,2};
    for(unsigned i=0;i<3;i++){assert(rx[out]==channels[i]);assert(smeg_mcu_crc_valid(rx+out,rx[out+2]+3));out+=rx[out+2]+5;}
    assert(s.net_count==0);
    /* Native EC sync resets all notification queues. */
    assert(smeg_mcu_peer_net(&s,5,parking,8));
    const uint8_t sync[9]={0xec,0xaa,0x55,0xff,0,0xaa,0x55,0xfb,0x8d};memcpy(tx,sync,9);
    assert(smeg_mcu_peer_exchange(&s,tx,rx));assert(!s.net_count&&!s.net_head);
    puts("Native NET whitelist, raw payloads, coalescing, CRC, bounds, multiplexing and reset passed");
}
