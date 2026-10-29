#include <assert.h>
#include <stdio.h>
#include "emulation/smeg_mcu_peer.h"
static void upg_request(uint8_t tx[92], uint8_t command,
                        const uint8_t *payload, unsigned len)
{
    memset(tx, 0xff, 92);
    tx[0] = 0xaa; tx[1] = 1;
    tx[2] = 0x10; tx[3] = command; tx[4] = len;
    memcpy(tx + 5, payload, len);
    smeg_mcu_seal(tx + 2, len + 3);
    smeg_mcu_seal(tx, 90);
}
static void upg_ack(SmegMcuPeer *s, uint8_t expected)
{
    uint8_t tx[92], rx[92];
    memset(tx, 0xff, sizeof tx);
    tx[0] = 0x0f; tx[1] = 0; smeg_mcu_seal(tx, 90);
    assert(smeg_mcu_peer_exchange(s, tx, rx));
    assert(rx[0] == 0x6b && rx[1] == 1 && rx[2] == 0x10);
    assert(rx[4] == expected && smeg_mcu_crc_valid(rx, 90));
}
static void test_upg_release(void)
{
    SmegMcuPeer s;
    uint8_t identity[4] = {5, 3, 9, 1}, tx[92], rx[92];
    uint8_t release[3] = {5, 0xe3, 1}, query = 0x5a;
    smeg_mcu_peer_init(&s, identity);
    upg_request(tx, 1, &query, 1);
    assert(smeg_mcu_peer_exchange(&s, tx, rx) && rx[1] == 0);
    upg_ack(&s, 0xf9); /* Disabled query retains ordinary transport ACK. */
    smeg_mcu_peer_set_upg_sw_release(&s, release);
    release[0] = 0x77; /* Setter copies caller's explicit state. */
    for (unsigned retry = 0; retry < 2; retry++) {
        upg_request(tx, 1, &query, 1);
        assert(smeg_mcu_peer_exchange(&s, tx, rx));
        const uint8_t expected[] = {0x10, 2, 3, 5, 0xe3, 1};
        assert(rx[0] == 0x99 && rx[1] == 1);
        assert(!memcmp(rx + 2, expected, sizeof expected));
        assert(smeg_mcu_crc_valid(rx + 2, 6) && smeg_mcu_crc_valid(rx, 90));
        upg_ack(&s, 0xf9);
    }
    /* Application CRC corruption must not produce a release reply. */
    upg_request(tx, 1, &query, 1);
    tx[6] ^= 1; smeg_mcu_seal(tx, 90);
    assert(smeg_mcu_peer_exchange(&s, tx, rx) && rx[1] == 0);
    upg_ack(&s, 0xfa);
    upg_request(tx, 1, &query, 1);
    tx[90] ^= 1;
    assert(!smeg_mcu_peer_exchange(&s, tx, rx));
    /* Wrong command, selector, length and channel remain unsupported. */
    const uint8_t commands[] = {0, 2, 3, 4, 0x10, 0x15, 0x20, 0x25, 0x30};
    for (unsigned i = 0; i < sizeof commands; i++) {
        upg_request(tx, commands[i], &query, 1);
        assert(smeg_mcu_peer_exchange(&s, tx, rx) && rx[1] == 0);
        upg_ack(&s, 0xf9); /* Transport ACK does not imply flash success. */
    }
    uint8_t bad_selector = 0x59, too_long[2] = {0x5a, 0};
    upg_request(tx, 1, &bad_selector, 1);
    assert(smeg_mcu_peer_exchange(&s, tx, rx) && rx[1] == 0);
    upg_request(tx, 1, too_long, 2);
    assert(smeg_mcu_peer_exchange(&s, tx, rx) && rx[1] == 0);
    upg_request(tx, 1, &query, 0);
    assert(smeg_mcu_peer_exchange(&s, tx, rx) && rx[1] == 0);
    upg_request(tx, 1, &query, 1);
    tx[2] = 0x11; smeg_mcu_seal(tx + 2, 4); smeg_mcu_seal(tx, 90);
    assert(smeg_mcu_peer_exchange(&s, tx, rx) && rx[1] == 0);
    smeg_mcu_peer_set_upg_sw_release(&s, NULL);
    upg_request(tx, 1, &query, 1);
    assert(smeg_mcu_peer_exchange(&s, tx, rx) && rx[1] == 0);
    assert(!s.upg_sw_release_enabled && s.upg_sw_release[0] == 0);
}
int main(void) {
    test_upg_release();
    SmegMcuPeer s; uint8_t id[4]={5,3,9,1}, tx[92], rx[92];
    smeg_mcu_peer_init(&s,id); memset(tx,255,92);
    /* Captured native startup begins with AA00, not an EC sync exchange. */
    memset(tx,255,92); tx[0]=0xaa; tx[1]=0; smeg_mcu_seal(tx,90);
    assert(tx[90]==0x21 && tx[91]==0x5c);
    assert(smeg_mcu_peer_exchange(&s,tx,rx));
    assert(rx[0]==0x99 && rx[1]==0 && smeg_mcu_crc_valid(rx,90));
    uint8_t sync[]={0xec,0xaa,0x55,0xff,0,0xaa,0x55,0xfb,0x8d};
    memcpy(tx,sync,9); assert(smeg_mcu_peer_exchange(&s,tx,rx));
    assert(rx[0]==0xd9 && smeg_mcu_crc_valid(rx,7));
    memset(tx,255,92); tx[0]=0xaa; tx[1]=1;
    tx[2]=0x40; tx[3]=1; tx[4]=1; tx[5]=0x5a;
    smeg_mcu_seal(tx+2,4); smeg_mcu_seal(tx,90);
    assert(smeg_mcu_peer_exchange(&s,tx,rx));
    assert(rx[0]==0x99 && rx[1]==2 && !memcmp(rx+5,id,4));
    assert(smeg_mcu_crc_valid(rx+2,7) && smeg_mcu_crc_valid(rx,90));
    assert(rx[11]==0x40 && rx[12]==4 && rx[13]==1 && rx[14]==7);
    const uint8_t libcom_on[]={0x40,4,1,7,0x18,0xb1};
    assert(!memcmp(rx+11,libcom_on,sizeof libcom_on));
    assert(smeg_mcu_crc_valid(rx+11,4));
    for(unsigned i=0;i<92;i++) { printf("%02x",rx[i]); } puts("");
    memset(tx,255,92);tx[0]=0x0f;tx[1]=0;smeg_mcu_seal(tx,90);
    assert(smeg_mcu_peer_exchange(&s,tx,rx));
    assert(rx[0]==0x6b && rx[1]==1 && rx[2]==0x40 && rx[3]==1 && rx[4]==0xf9);
    assert(smeg_mcu_crc_valid(rx,90));
    memset(tx,255,92); tx[0]=0xaa; tx[1]=1;
    tx[2]=0x40; tx[3]=4; tx[4]=1; tx[5]=1;
    smeg_mcu_seal(tx+2,4); smeg_mcu_seal(tx,90);
    assert(smeg_mcu_peer_exchange(&s,tx,rx));
    assert(rx[0]==0x99 && rx[1]==1 && rx[3]==5 && rx[4]==4);
    assert(rx[5]==0 && rx[6]==0 && rx[7]==0 && rx[8]==4);
    assert(smeg_mcu_crc_valid(rx+2,7) && smeg_mcu_crc_valid(rx,90));
    /* Native app channel opens later: announce KEY_ON once, not forever. */
    memset(tx,255,92); tx[0]=0xaa; tx[1]=1;
    tx[2]=1; tx[3]=1; tx[4]=2; tx[5]=0; tx[6]=0x20;
    smeg_mcu_seal(tx+2,5); smeg_mcu_seal(tx,90);
    assert(smeg_mcu_peer_exchange(&s,tx,rx));
    assert(rx[1]==1 && rx[2]==1 && rx[3]==1 && rx[4]==2);
    const uint8_t fp_on[]={1,1,2,7,0,0xef,0x4f};
    assert(!memcmp(rx+2,fp_on,sizeof fp_on));
    assert(rx[5]==7 && rx[6]==0 && smeg_mcu_crc_valid(rx+2,5));
    assert(smeg_mcu_peer_exchange(&s,tx,rx) && rx[1]==0);
    /* Init must not race the transport ACK: the client sets its expected
     * sequence only after Write returns. Deliver on the following AA poll. */
    uint8_t old_tx[92];memcpy(old_tx,tx,92);
    memset(tx,255,92);tx[0]=0xaa;tx[1]=1;
    tx[2]=0x40;tx[3]=3;tx[4]=1;tx[5]=1;
    smeg_mcu_seal(tx+2,4);smeg_mcu_seal(tx,90);
    assert(smeg_mcu_peer_exchange(&s,tx,rx)&&rx[1]==0);
    tx[0]=0x0f;tx[1]=0;smeg_mcu_seal(tx,90);
    assert(smeg_mcu_peer_exchange(&s,tx,rx));
    assert(rx[1]==1&&rx[2]==0x40&&rx[3]==3&&rx[4]==0xf9);
    memset(tx,255,92);tx[0]=0xaa;tx[1]=0;smeg_mcu_seal(tx,90);
    assert(smeg_mcu_peer_exchange(&s,tx,rx));
    assert(rx[1]==1&&rx[2]==0x40&&rx[3]==3&&rx[4]==1&&rx[5]==1);
    assert(smeg_mcu_crc_valid(rx+2,4)&&smeg_mcu_crc_valid(rx,90));
    assert(smeg_mcu_peer_exchange(&s,tx,rx)&&rx[1]==0);
    memcpy(tx,old_tx,92);
    uint8_t poll[92]; memcpy(poll,tx,92);
    memcpy(tx,sync,9); assert(smeg_mcu_peer_exchange(&s,tx,rx));
    assert(!s.libcom_power_sent && !s.fp_power_sent);
    assert(smeg_mcu_peer_exchange(&s,poll,rx));
    assert(rx[1]==1 && rx[5]==7 && rx[6]==0);
    assert(smeg_mcu_crc_valid(rx+2,5) && smeg_mcu_crc_valid(rx,90));
    memcpy(tx,poll,92);
    tx[90]^=1;assert(!smeg_mcu_peer_exchange(&s,tx,rx));
    puts("peer CRC, sync, identity, diagnostic display config, ACK, query-only UPG release and corrupt-frame checks passed");
}
