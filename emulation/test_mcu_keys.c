#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "smeg_mcu_peer.h"
static void empty_frame(uint8_t *p, uint8_t kind)
{
    memset(p, 0xff, 92); p[0] = kind; p[1] = 0; smeg_mcu_seal(p, 90);
}
static void verify(const uint8_t *rx, unsigned at, uint8_t id, uint8_t status)
{
    assert(rx[0] == 0x99 && smeg_mcu_crc_valid(rx, 90));
    assert(rx[at] == 8 && rx[at + 1] == id && rx[at + 2] == 1);
    assert(rx[at + 3] == status && smeg_mcu_crc_valid(rx + at, 4));
}
int main(void)
{
    SmegMcuPeer s;
    const uint8_t ident[4] = {5, 3, 9, 1};
    uint8_t tx[92], rx[92], before[92], padding[83] = {0};
    smeg_mcu_peer_init(&s, ident);
    assert(!smeg_mcu_peer_key(&s, 0x45, 1));
    assert(!smeg_mcu_peer_key(&s, 0, 0));
    assert(!smeg_mcu_peer_key(&s, 0, 11));
    for (unsigned i = 0; i < SMEG_MCU_KEY_QUEUE; i++)
        assert(smeg_mcu_peer_key(&s, i, i % 10 + 1));
    assert(!smeg_mcu_peer_key(&s, 0x44, 10));
    empty_frame(tx, 0xaa);
    for (unsigned i = 0; i < SMEG_MCU_KEY_QUEUE; i++) {
        assert(smeg_mcu_peer_exchange(&s, tx, rx));
        assert(rx[1] == 1); verify(rx, 2, i, i % 10 + 1);
        assert(s.key_count == SMEG_MCU_KEY_QUEUE - i - 1);
    }
    /* Ring wrap and one key per original host exchange. */
    for (unsigned i = 0; i < 100; i++) {
        assert(smeg_mcu_peer_key(&s, 0x44, 10));
        assert(smeg_mcu_peer_key(&s, 0x17, 2));
        assert(smeg_mcu_peer_exchange(&s, tx, rx)); verify(rx, 2, 0x44, 10);
        memcpy(before, rx, 92);
        assert(!smeg_mcu_peer_key_pending(&s, rx));
        assert(!memcmp(before, rx, 92) && s.key_count == 1);
        assert(smeg_mcu_peer_exchange(&s, tx, rx)); verify(rx, 2, 0x17, 2);
    }
    /* Touch and key use separate native IDs and valid nested checksums. */
    assert(smeg_mcu_peer_touch(&s, 220, 675, 128, 17, 0x81));
    assert(smeg_mcu_peer_key(&s, 0x16, 2));
    assert(smeg_mcu_peer_exchange(&s, tx, rx));
    assert(rx[1] == 2 && rx[3] == 0x80 && smeg_mcu_crc_valid(rx + 2, 10));
    verify(rx, 14, 0x16, 2);
    /* Pending delivery never consumes on wrong type, CRC or malformed bounds. */
    assert(smeg_mcu_peer_key(&s, 0x1a, 2));
    empty_frame(rx, 0x6b); assert(!smeg_mcu_peer_key_pending(&s, rx));
    empty_frame(rx, 0x99); rx[91] ^= 1; assert(!smeg_mcu_peer_key_pending(&s, rx));
    empty_frame(rx, 0x99); rx[1] = 1; rx[4] = 255; smeg_mcu_seal(rx, 90);
    assert(!smeg_mcu_peer_key_pending(&s, rx));
    empty_frame(rx, 0x99);
    assert(smeg_mcu_append(rx, 2, 1, 4, padding, 83) == 90);
    smeg_mcu_seal(rx, 90); memcpy(before, rx, 92);
    assert(!smeg_mcu_peer_key_pending(&s, rx)); assert(!memcmp(before, rx, 92));
    /* An invalid inner CRC is rejected even when the frame CRC is correct. */
    empty_frame(rx, 0x99); smeg_mcu_append(rx, 2, 1, 4, padding, 1);
    rx[6] ^= 1; smeg_mcu_seal(rx, 90);
    assert(!smeg_mcu_peer_key_pending(&s, rx) && s.key_count == 1);
    empty_frame(rx, 0x99); assert(smeg_mcu_peer_key_pending(&s, rx));
    verify(rx, 2, 0x1a, 2); assert(s.key_count == 0);
    /* Both transport synchronization and initialization discard stale events. */
    assert(smeg_mcu_peer_key(&s, 0x1b, 1));
    memset(tx, 0xff, 92);
    const uint8_t sync[9] = {0xec, 0xaa, 0x55, 0xff, 0, 0xaa, 0x55, 0xfb, 0x8d};
    memcpy(tx, sync, 9); assert(smeg_mcu_peer_exchange(&s, tx, rx));
    assert(s.key_count == 0 && s.key_head == 0);
    assert(smeg_mcu_peer_key(&s, 0x14, 1)); smeg_mcu_peer_init(&s, ident);
    assert(s.key_count == 0 && s.key_head == 0);
    puts("native MCU key FIFO tests passed");
    return 0;
}
