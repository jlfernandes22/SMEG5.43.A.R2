#include <assert.h>
#include <stdio.h>
#include "emulation/smeg_mcu_peer.h"

static void empty(uint8_t frame[92], uint8_t type)
{
    memset(frame, 255, 92); frame[0]=type; frame[1]=0;
    smeg_mcu_seal(frame,90);
}
int main(void)
{
    SmegMcuPeer s; uint8_t tx[92],rx[92],saved[92];
    const uint8_t identity[4]={5,3,9,1};
    smeg_mcu_peer_init(&s,identity);
    assert(!smeg_mcu_peer_set_key_variant(&s,0xa1));
    s.bench_key_profile=1; s.libcom_power_sent=s.fp_power_sent=1;
    assert(!smeg_mcu_peer_set_key_variant(&s,1));
    assert(smeg_mcu_peer_set_key_variant(&s,0xa1));
    assert(smeg_mcu_peer_key(&s,0,2));
    empty(rx,0x99); memcpy(saved,rx,92); rx[91]^=1;
    assert(!smeg_mcu_peer_profile_pending(&s,rx));
    assert(s.key_profile_pending && s.key_count==1);
    memcpy(rx,saved,92);
    assert(!smeg_mcu_peer_key_pending(&s,rx));
    assert(smeg_mcu_peer_profile_pending(&s,rx));
    assert(rx[1]==1 && rx[2]==1 && rx[3]==0x10 && rx[4]==17);
    assert(rx[6]==0xa1 && smeg_mcu_crc_valid(rx+2,20));
    assert(smeg_mcu_crc_valid(rx,90));
    for(unsigned i=0;i<17;i++)if(i!=1)assert(rx[5+i]==0);
    assert(!smeg_mcu_peer_key_pending(&s,rx));
    assert(s.key_count==1);
    empty(tx,0xaa);assert(smeg_mcu_peer_exchange(&s,tx,rx));
    assert(rx[1]==1 && rx[2]==8 && rx[3]==0 && rx[5]==2 && !s.key_count);
    assert(smeg_mcu_peer_set_key_variant(&s,0xa1) && !s.key_profile_pending);
    assert(smeg_mcu_peer_set_key_variant(&s,0));
    assert(smeg_mcu_peer_key(&s,0x3e,1));
    empty(tx,0xaa);assert(smeg_mcu_peer_exchange(&s,tx,rx));
    assert(rx[1]==1 && rx[2]==1 && rx[3]==0x10 && rx[6]==0 && s.key_count==1);
    assert(smeg_mcu_peer_exchange(&s,tx,rx));
    assert(rx[2]==8 && rx[3]==0x3e && rx[5]==1 && !s.key_count);
    /* No profile update fits in a full validated frame: retain pending state. */
    assert(smeg_mcu_peer_set_key_variant(&s,0xa1));
    empty(rx,0x99); uint8_t payload[65]={0};
    assert(smeg_mcu_append(rx,2,2,0x15,payload,sizeof(payload))==72);
    smeg_mcu_seal(rx,90);memcpy(saved,rx,92);
    assert(!smeg_mcu_peer_profile_pending(&s,rx));
    assert(s.key_profile_pending && !memcmp(saved,rx,92));
    /* Explicit board reset restores default; identity remains untouched. */
    smeg_mcu_peer_init(&s,identity);
    assert(!s.key_variant && !s.key_profile_pending && !memcmp(s.identity,identity,4));
    puts("Native MCU profile switching: opt-in, whitelist, CRC, ordered profile/key frames, idempotence, full-frame retry and reset passed");
}
