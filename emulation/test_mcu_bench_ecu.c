#include <assert.h>
#include <stdio.h>
#include "emulation/smeg_mcu_peer.h"
static void request(uint8_t tx[92],uint8_t channel,uint8_t id,unsigned len,unsigned eco,unsigned park)
{
    uint8_t data[8]={0};data[6]=eco?0x80:0;data[3]=park?4:0;
    memset(tx,255,92);tx[0]=0xaa;tx[1]=0;
    smeg_mcu_append(tx,2,channel,id,data,len);smeg_mcu_seal(tx,90);
}
static void ack(SmegMcuPeer *s)
{
    uint8_t tx[92],rx[92];memset(tx,255,92);tx[0]=0x0f;tx[1]=0;smeg_mcu_seal(tx,90);
    assert(smeg_mcu_peer_exchange(s,tx,rx));assert(rx[0]==0x6b&&smeg_mcu_crc_valid(rx,90));
}
static void counts(SmegMcuPeer*s,unsigned eco,unsigned park)
{assert(s->ecu_toggle_count[0]==eco&&s->ecu_toggle_count[1]==park);}
int main(void)
{
    const uint8_t id[4]={5,3,9,1};SmegMcuPeer s;uint8_t tx[92],rx[92];
    smeg_mcu_peer_init(&s,id);request(tx,2,3,8,1,1);
    assert(!s.bench_ecu_mask);assert(smeg_mcu_peer_exchange(&s,tx,rx));counts(&s,0,0);
    /* Each fixture is independently opt-in. */
    s.bench_ecu_mask=1;assert(smeg_mcu_peer_exchange(&s,tx,rx));counts(&s,1,0);
    ack(&s);s.bench_ecu_mask=2;assert(smeg_mcu_peer_exchange(&s,tx,rx));counts(&s,1,1);
    ack(&s);s.bench_ecu_mask=3;assert(smeg_mcu_peer_exchange(&s,tx,rx));counts(&s,2,2);
    /* Exact retransmissions before ACK count once; no zero-bit frame needed
     * between two legitimate requests separated by native ACK/control cycle. */
    for(unsigned i=0;i<20;i++){assert(smeg_mcu_peer_exchange(&s,tx,rx));}
    counts(&s,2,2);
    uint8_t corrupt_ack[92];memset(corrupt_ack,255,92);corrupt_ack[0]=0x0f;corrupt_ack[1]=0;smeg_mcu_seal(corrupt_ack,90);corrupt_ack[91]^=1;
    assert(!smeg_mcu_peer_exchange(&s,corrupt_ack,rx));
    assert(smeg_mcu_peer_exchange(&s,tx,rx));counts(&s,2,2);
    ack(&s);assert(smeg_mcu_peer_exchange(&s,tx,rx));counts(&s,3,3);
    assert(smeg_mcu_peer_take_ecu_toggles(&s,0)==3);counts(&s,0,3);
    assert(smeg_mcu_peer_take_ecu_toggles(&s,0)==0);
    assert(smeg_mcu_peer_take_ecu_toggles(&s,9)==0);counts(&s,0,3);
    assert(smeg_mcu_peer_take_ecu_toggles(&s,1)==3);counts(&s,0,0);
    /* Whitelist and semantic pulse checks. Unknown ASR commands are untouched. */
    for(unsigned i=0;i<4;i++){
        ack(&s);request(tx,i==0?1:2,i==1?4:3,i==2?7:8,i==3?0:1,i==3?0:1);
        assert(smeg_mcu_peer_exchange(&s,tx,rx));counts(&s,0,0);
    }
    ack(&s);request(tx,2,3,8,1,1);tx[91]^=1;
    assert(!smeg_mcu_peer_exchange(&s,tx,rx));counts(&s,0,0);
    request(tx,2,3,8,1,1);tx[5]^=1;smeg_mcu_seal(tx,90);
    assert(smeg_mcu_peer_exchange(&s,tx,rx));counts(&s,0,0); /* Inner CRC error. */
    ack(&s);request(tx,2,3,8,1,1);tx[1]=2;tx[17]=0xff;smeg_mcu_seal(tx,90);
    assert(!smeg_mcu_peer_exchange(&s,tx,rx));counts(&s,0,0); /* Malformed later message. */
    /* Saturation cannot wrap and turn a pending count into zero. */
    s.ecu_toggle_count[0]=s.ecu_toggle_count[1]=UINT32_MAX;ack(&s);
    request(tx,2,3,8,1,1);assert(smeg_mcu_peer_exchange(&s,tx,rx));counts(&s,UINT32_MAX,UINT32_MAX);
    const uint8_t sync[9]={0xec,0xaa,0x55,0xff,0,0xaa,0x55,0xfb,0x8d};memcpy(tx,sync,9);
    assert(smeg_mcu_peer_exchange(&s,tx,rx));counts(&s,0,0);
    assert(s.bench_ecu_mask==3&&!s.ecu_awaiting_ack); /* Configuration survives sync. */
    request(tx,2,3,8,1,1);assert(smeg_mcu_peer_exchange(&s,tx,rx));counts(&s,1,1);
    puts("Opt-in ECU pulses: fixture masks, ACK retry boundary, repeated requests, CRC, bounds, drain, saturation and sync passed");
}
