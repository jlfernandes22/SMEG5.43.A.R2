#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "smeg_mcu_peer.h"
static unsigned decode_x(const uint8_t *m) { return (unsigned)m[3] << 4 | m[4] >> 4; }
static unsigned decode_ms(const uint8_t *m) { return (unsigned)m[7] << 8 | m[8]; }
static void frame(SmegMcuPeer *peer, uint8_t *tx, uint8_t *rx)
{
    assert(smeg_mcu_peer_exchange(peer, tx, rx));
    assert(rx[0] == 0x99 && rx[1] == 1 && smeg_mcu_crc_valid(rx, 90));
    assert(rx[2] == 8 && rx[3] == 0x80 && rx[4] == 7);
    assert(smeg_mcu_crc_valid(rx + 2, 10));
}
int main(void)
{
    SmegMcuPeer peer;
    const uint8_t id[4] = {5,3,9,1};
    uint8_t tx[92], rx[92];
    smeg_mcu_peer_init(&peer,id);
    memset(tx,255,sizeof(tx)); tx[0]=0xaa; tx[1]=0; smeg_mcu_seal(tx,90);
    assert(smeg_mcu_peer_touch(&peer,799,479,128,0x1234,0x81));
    assert(smeg_mcu_peer_touch(&peer,799,479,0,0x1248,0x01));
    frame(&peer,tx,rx);
    const uint8_t press[10]={8,0x80,7,0x31,0xf1,0xdf,128,0x12,0x34,0x81};
    assert(!memcmp(rx+2,press,sizeof(press)) && peer.touch_count==1);
    frame(&peer,tx,rx);
    assert(rx[8]==0 && rx[11]==1 && peer.touch_count==0);
    /* A long hold retains its first and freshest sample, then two release
     * samples for the native filters; no old motion train delays release. */
    for(unsigned i=0;i<2000;i++)
        assert(smeg_mcu_peer_touch(&peer,i%800,675,128,(uint16_t)(20*i),0x81));
    assert(peer.touch_count==2);
    for(unsigned i=2000;i<2010;i++)
        assert(smeg_mcu_peer_touch(&peer,220,675,0,(uint16_t)(20*i),1));
    assert(peer.touch_count==4);
    const unsigned positions[4]={0,1999%800,220,220};
    const unsigned times[4]={0,39980,40000,40180};
    for(unsigned i=0;i<4;i++) {
        frame(&peer,tx,rx);
        assert(decode_x(rx+2)==positions[i] && decode_ms(rx+2)==times[i]);
        assert(rx[8]==(i<2?128:0));
    }
    assert(peer.touch_count==0);
    /* Alternating contact edges never coalesce, wrap, or overwrite. */
    for(unsigned i=0;i<64;i++)
        assert(smeg_mcu_peer_touch(&peer,i,2*i,(i&1)?0:128,20*i,(i&1)?1:0x81));
    assert(!smeg_mcu_peer_touch(&peer,0,0,128,0,0x81));
    for(unsigned i=0;i<64;i++) {
        frame(&peer,tx,rx);
        assert(decode_x(rx+2)==i && rx[8]==((i&1)?0:128));
    }
    /* Exercise ring wrap and coalescing with a nonzero head. */
    for(unsigned cycle=0;cycle<70;cycle++) {
        for(unsigned i=0;i<5;i++)
            assert(smeg_mcu_peer_touch(&peer,i,675,128,20*i,0x81));
        assert(peer.touch_count==2);
        frame(&peer,tx,rx); assert(decode_x(rx+2)==0);
        frame(&peer,tx,rx); assert(decode_x(rx+2)==4);
    }
    /* A late edge may enter a response before RX clocks, never after it
     * already carries another touch; ACK/control frames stay untouched. */
    assert(smeg_mcu_peer_exchange(&peer,tx,rx) && rx[1]==0);
    assert(smeg_mcu_peer_touch(&peer,220,675,128,100,0x81));
    assert(smeg_mcu_peer_touch_pending(&peer,rx));
    assert(rx[1]==1 && smeg_mcu_crc_valid(rx,90));
    assert(smeg_mcu_peer_touch(&peer,221,675,128,120,0x81));
    assert(!smeg_mcu_peer_touch_pending(&peer,rx) && peer.touch_count==1);
    rx[0]=0x6b; smeg_mcu_seal(rx,90);
    assert(!smeg_mcu_peer_touch_pending(&peer,rx) && peer.touch_count==1);
    frame(&peer,tx,rx); assert(decode_x(rx+2)==221);
    puts("Tactile edges, fresh repeat coalescing, native single-sample pacing, bounds and CRC passed");
}
