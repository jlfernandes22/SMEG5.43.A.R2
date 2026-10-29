#include <assert.h>
#include <stdio.h>
#include "emulation/smeg_bench_ecu.h"

static void packet(uint8_t tx[92], unsigned channel, unsigned id, unsigned len,
                   unsigned d0, unsigned d1, unsigned d3)
{
    uint8_t data[8]={0}; data[0]=d0; data[1]=d1; data[3]=d3;
    memset(tx,255,92); tx[0]=0xaa; tx[1]=0;
    smeg_mcu_append(tx,2,channel,id,data,len); smeg_mcu_seal(tx,90);
}
static void ack(SmegMcuPeer *s)
{
    uint8_t tx[92],rx[92]; memset(tx,255,92);tx[0]=0x0f;tx[1]=0;
    smeg_mcu_seal(tx,90);assert(smeg_mcu_peer_exchange(s,tx,rx));
}
static void expect_only_bit(const uint8_t before[8], const uint8_t after[8], unsigned on)
{
    for(unsigned i=0;i<8;i++)
        assert(after[i]==(i==3?((before[i]&~8U)|(on?8:0)):before[i]));
}
int main(void)
{
    const uint8_t identity[4]={5,3,9,1};
    SmegMcuPeer s; uint8_t tx[92],rx[92];
    uint8_t status[8]={0xa5,0xb6,0xc7,0xd0,0xe9,0xfa,0x1b,0x2c},before[8];
    memcpy(before,status,8);smeg_mcu_peer_init(&s,identity);
    packet(tx,2,9,7,0,4,8);assert(smeg_mcu_peer_exchange(&s,tx,rx));
    assert(!s.body_pending&&!smeg_bench_body_apply(&s,status,1));
    s.bench_ecu_mask=4;assert(smeg_mcu_peer_exchange(&s,tx,rx));
    assert(s.body_pending&&s.body_level==8);
    assert(smeg_bench_body_apply(&s,status,1));expect_only_bit(before,status,1);
    assert(!s.body_pending&&!smeg_bench_body_apply(&s,status,1));
    /* Retry before ACK, and a new identical commit after ACK, are idempotent. */
    assert(smeg_mcu_peer_exchange(&s,tx,rx));assert(!s.body_pending);
    ack(&s);assert(smeg_mcu_peer_exchange(&s,tx,rx));
    assert(s.body_pending&&!smeg_bench_body_apply(&s,status,1));
    ack(&s);packet(tx,2,9,7,0,4,0);assert(smeg_mcu_peer_exchange(&s,tx,rx));
    assert(smeg_bench_body_apply(&s,status,1));expect_only_bit(before,status,0);
    /* Latest complete bitmap wins, without counting edges. */
    ack(&s);packet(tx,2,9,7,0,4,8);assert(smeg_mcu_peer_exchange(&s,tx,rx));
    ack(&s);packet(tx,2,9,7,0,4,0);assert(smeg_mcu_peer_exchange(&s,tx,rx));
    assert(s.body_pending&&!smeg_bench_body_apply(&s,status,1));
    /* Language, absent marker, wrong channel/ID/size and invalid inner CRC. */
    const unsigned invalid[][6]={{2,9,7,0x80,4,8},{2,9,7,0,0,8},
        {1,9,7,0,4,8},{2,8,7,0,4,8},{2,9,6,0,4,8},{2,9,8,0,4,8}};
    for(unsigned i=0;i<sizeof(invalid)/sizeof(*invalid);i++) {
        ack(&s);packet(tx,invalid[i][0],invalid[i][1],invalid[i][2],
                       invalid[i][3],invalid[i][4],invalid[i][5]);
        assert(smeg_mcu_peer_exchange(&s,tx,rx));assert(!s.body_pending);
    }
    ack(&s);packet(tx,2,9,7,0,4,8);tx[8]^=1;smeg_mcu_seal(tx,90);
    assert(smeg_mcu_peer_exchange(&s,tx,rx));assert(!s.body_pending);
    ack(&s);packet(tx,2,9,7,0,4,8);tx[91]^=1;
    assert(!smeg_mcu_peer_exchange(&s,tx,rx));assert(!s.body_pending);
    packet(tx,2,9,7,0,4,8);tx[1]=2;tx[16]=255;smeg_mcu_seal(tx,90);
    assert(!smeg_mcu_peer_exchange(&s,tx,rx));assert(!s.body_pending);
    /* Missing fixture drains state, so later appearance cannot apply stale data. */
    packet(tx,2,9,7,0,4,8);assert(smeg_mcu_peer_exchange(&s,tx,rx));
    assert(!smeg_bench_body_apply(&s,status,0)&&!s.body_pending);
    assert(!smeg_bench_body_apply(&s,status,1));expect_only_bit(before,status,0);
    ack(&s);assert(smeg_mcu_peer_exchange(&s,tx,rx));
    assert(!smeg_bench_body_apply(&s,NULL,1)&&!s.body_pending);
    ack(&s);assert(smeg_mcu_peer_exchange(&s,tx,rx));
    const uint8_t sync[9]={0xec,0xaa,0x55,0xff,0,0xaa,0x55,0xfb,0x8d};
    memcpy(tx,sync,9);assert(smeg_mcu_peer_exchange(&s,tx,rx));
    assert(!s.body_pending&&!s.body_level&&s.bench_ecu_mask==4);
    assert(!s.ecu_toggle_count[0]&&!s.ecu_toggle_count[1]);
    smeg_mcu_peer_init(&s,identity);assert(!s.bench_ecu_mask&&!s.body_pending);
    puts("Welcome Lighting bench level: opt-in, markers, exact frame, CRC/bounds, idempotence, latest-state, preserved bits, drain and reset passed");
}
