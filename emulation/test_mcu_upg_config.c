#include <assert.h>
#include <stdio.h>
#include "emulation/smeg_mcu_peer.h"

static void request(uint8_t tx[92], unsigned id, const uint8_t *data, unsigned n)
{
    memset(tx, 255, 92); tx[0]=0xaa; tx[1]=1;
    tx[2]=0x10; tx[3]=id; tx[4]=n;
    memcpy(tx+5,data,n); smeg_mcu_seal(tx+2,n+3); smeg_mcu_seal(tx,90);
}
static void reply(const uint8_t rx[92], unsigned id,
                  const uint8_t *data, unsigned n)
{
    assert(rx[0]==0x99 && rx[1]==1 && rx[2]==0x10);
    assert(rx[3]==id && rx[4]==n && !memcmp(rx+5,data,n));
    assert(smeg_mcu_crc_valid(rx+2,n+3) && smeg_mcu_crc_valid(rx,90));
}
int main(void)
{
    SmegMcuPeer s; const uint8_t identity[4]={5,3,9,1};
    uint8_t tx[92],rx[92],query[17],update[17],expected[17];
    uint8_t upg[16],system[16];
    for(unsigned i=0;i<16;i++){upg[i]=i;system[i]=0xf0+i;}
    memset(query,0x5c,17);query[0]=0x40; /* Native GET tail is unspecified. */
    smeg_mcu_peer_init(&s,identity);
    for(unsigned id=8;id<=9;id++) {
        request(tx,id,query,17);
        assert(smeg_mcu_peer_exchange(&s,tx,rx) && rx[1]==0);
    }
    smeg_mcu_peer_set_upg_config(&s,upg);
    smeg_mcu_peer_set_system_config(&s,system);
    upg[0]=0xee;system[0]=0xee; /* Fixtures are copied, never borrowed. */
    request(tx,9,query,17);assert(smeg_mcu_peer_exchange(&s,tx,rx));
    expected[0]=0x80;memcpy(expected+1,s.upg_config,16);reply(rx,9,expected,17);
    request(tx,8,query,17);assert(smeg_mcu_peer_exchange(&s,tx,rx));
    reply(rx,7,s.system_config,16);
    for(unsigned id=8;id<=9;id++) {
        update[0]=0x80;
        for(unsigned i=1;i<17;i++)update[i]=id*16+i;
        for(unsigned retry=0;retry<2;retry++) {
            request(tx,id,update,17);assert(smeg_mcu_peer_exchange(&s,tx,rx));
            uint8_t *state=id==9?s.upg_config:s.system_config;
            assert(!memcmp(state,update+1,16)); /* Updated before success reply. */
            const uint8_t upg_written[]={0,0x20},system_written=0x80;
            reply(rx,id==9?4:8,id==9?upg_written:&system_written,id==9?2:1);
            request(tx,id,query,17);assert(smeg_mcu_peer_exchange(&s,tx,rx));
            if(id==9){expected[0]=0x80;memcpy(expected+1,update+1,16);reply(rx,9,expected,17);}
            else reply(rx,7,update+1,16);
        }
        uint8_t before[16];memcpy(before,id==9?s.upg_config:s.system_config,16);
        request(tx,id,update,17);tx[5]^=1;smeg_mcu_seal(tx,90);
        assert(smeg_mcu_peer_exchange(&s,tx,rx)&&rx[1]==0);
        assert(!memcmp(before,id==9?s.upg_config:s.system_config,16));
        request(tx,id,update,17);tx[91]^=1;
        assert(!smeg_mcu_peer_exchange(&s,tx,rx));
        assert(!memcmp(before,id==9?s.upg_config:s.system_config,16));
        for(unsigned n=16;n<=18;n+=2) {
            uint8_t wrong_length[18]={0x80};request(tx,id,wrong_length,n);
            assert(smeg_mcu_peer_exchange(&s,tx,rx)&&rx[1]==0);
        }
        update[0]=0x81;request(tx,id,update,17);
        assert(smeg_mcu_peer_exchange(&s,tx,rx)&&rx[1]==0);
        assert(!memcmp(before,id==9?s.upg_config:s.system_config,16));
    }
    /* Neither config bank enables MCU loader/program/erase operations. */
    const uint8_t loader[]={0x34,0x5a};request(tx,3,loader,2);
    assert(smeg_mcu_peer_exchange(&s,tx,rx)&&rx[1]==0);
    /* EC transport resync preserves virtual NVRAM; full peer reset clears it. */
    const uint8_t sync[]={0xec,0xaa,0x55,0xff,0,0xaa,0x55,0xfb,0x8d};
    memcpy(tx,sync,9);assert(smeg_mcu_peer_exchange(&s,tx,rx));
    request(tx,9,query,17);assert(smeg_mcu_peer_exchange(&s,tx,rx));
    expected[0]=0x80;memcpy(expected+1,s.upg_config,16);reply(rx,9,expected,17);
    smeg_mcu_peer_set_upg_config(&s,NULL);
    request(tx,9,query,17);assert(smeg_mcu_peer_exchange(&s,tx,rx)&&rx[1]==0);
    assert(s.system_config_enabled);
    smeg_mcu_peer_set_system_config(&s,NULL);
    request(tx,8,query,17);assert(smeg_mcu_peer_exchange(&s,tx,rx)&&rx[1]==0);
    smeg_mcu_peer_init(&s,identity);
    assert(!s.upg_config_enabled&&!s.system_config_enabled);
    puts("Explicit virtual UPG/System config: copied fixtures, native get/set replies, retained writes, CRC/selector/length guards, duplicate requests, disable and reset passed");
}
