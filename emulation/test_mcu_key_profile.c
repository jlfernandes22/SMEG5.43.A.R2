#include <assert.h>
#include <stdio.h>
#include "emulation/smeg_mcu_peer.h"
static void request(uint8_t tx[92],uint8_t channel,uint8_t id,unsigned len,uint8_t p0,uint8_t p1)
{
    uint8_t p[2]={p0,p1};memset(tx,255,92);tx[0]=0xaa;tx[1]=0;
    assert(smeg_mcu_append(tx,2,channel,id,p,len)>2);smeg_mcu_seal(tx,90);
}
static unsigned profiles(const uint8_t rx[92])
{
    assert(rx[0]==0x99&&smeg_mcu_crc_valid(rx,90));unsigned out=2,found=0;
    for(unsigned i=0;i<rx[1];i++){
        assert(out+5<=90&&out+rx[out+2]+5<=90);
        assert(smeg_mcu_crc_valid(rx+out,rx[out+2]+3));
        if(rx[out]==1&&rx[out+1]==0x10){
            assert(rx[out+2]==17);for(unsigned j=0;j<17;j++)assert(!rx[out+3+j]);found++;
        }
        out+=rx[out+2]+5;
    }
    return found;
}
int main(void)
{
    SmegMcuPeer s;const uint8_t id[4]={5,3,9,1};uint8_t tx[92],rx[92];
    smeg_mcu_peer_init(&s,id);s.fp_power_sent=1;
    request(tx,1,0x10,2,0x80,1);assert(!s.bench_key_profile);
    assert(smeg_mcu_peer_exchange(&s,tx,rx));assert(!profiles(rx)&&!rx[1]);
    s.bench_key_profile=1;assert(smeg_mcu_peer_exchange(&s,tx,rx));
    assert(profiles(rx)==1&&rx[1]==1);assert(rx[2]==1&&rx[3]==0x10&&rx[4]==17);
    const uint8_t cases[][5]={{2,0x10,2,0x80,1},{1,0x11,2,0x80,1},
                            {1,0x10,1,0x80,1},{1,0x10,2,0,1},{1,0x10,2,0x80,2}};
    for(unsigned i=0;i<sizeof cases/sizeof cases[0];i++){
        request(tx,cases[i][0],cases[i][1],cases[i][2],cases[i][3],cases[i][4]);
        assert(smeg_mcu_peer_exchange(&s,tx,rx));assert(!profiles(rx));
    }
    request(tx,1,0x10,2,0x80,1);tx[5]^=1;smeg_mcu_seal(tx,90);
    assert(smeg_mcu_peer_exchange(&s,tx,rx));assert(!profiles(rx));
    memset(tx,255,92);tx[0]=0x0f;tx[1]=0;smeg_mcu_seal(tx,90);
    assert(smeg_mcu_peer_exchange(&s,tx,rx));assert(rx[0]==0x6b&&rx[4]==0xfa&&smeg_mcu_crc_valid(rx,90));
    request(tx,1,0x10,2,0x80,1);tx[91]^=1;assert(!smeg_mcu_peer_exchange(&s,tx,rx));
    /* Correct response coexists with native bench power-open notification. */
    s.fp_power_sent=0;request(tx,1,0x10,2,0x80,1);
    assert(smeg_mcu_peer_exchange(&s,tx,rx));assert(profiles(rx)==1&&rx[1]==2);
    assert(rx[24]==1&&rx[25]==1&&rx[26]==2&&rx[27]==7&&rx[28]==0);
    /* Many valid requests cannot overflow the fixed92-byte response. */
    memset(tx,255,92);tx[0]=0xaa;tx[1]=0;unsigned out=2;const uint8_t data[2]={0x80,1};
    while(out+7<=90)out=smeg_mcu_append(tx,out,1,0x10,data,2);
    smeg_mcu_seal(tx,90);assert(smeg_mcu_peer_exchange(&s,tx,rx));assert(profiles(rx)==4);
    /* Configured opt-in survives native resynchronization; profile remains
     * idempotent and does not change installed identity/table data. */
    const uint8_t sync[9]={0xec,0xaa,0x55,0xff,0,0xaa,0x55,0xfb,0x8d};memcpy(tx,sync,9);
    assert(smeg_mcu_peer_exchange(&s,tx,rx));assert(s.bench_key_profile==1&&!memcmp(s.identity,id,4));
    request(tx,1,0x10,2,0x80,1);assert(smeg_mcu_peer_exchange(&s,tx,rx));assert(profiles(rx)==1);
    puts("Opt-in default key profile: exact17-byte reply, CRC, request whitelist, bounds, power multiplexing and sync passed");
}
