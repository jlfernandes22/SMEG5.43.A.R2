#include <assert.h>
#include <stdio.h>
#include "emulation/smeg_mcu_peer.h"

static void empty(uint8_t frame[92])
{
    memset(frame, 255, 92);
    frame[0] = 0x99;
    frame[1] = 0;
    smeg_mcu_seal(frame, 90);
}

int main(void)
{
    const uint8_t identity[4] = {5, 3, 9, 1};
    const uint8_t config[5] = {0xa0, 0, 0, 0, 0};
    const uint8_t updated[5] = {0x80, 1, 2, 3, 4};
    SmegMcuPeer s;
    uint8_t frame[92], before[92];
    smeg_mcu_peer_init(&s, identity);
    /* Strictly whitelist the source-backed local ID and its native size. */
    for (unsigned n = 0; n <= 8; n++) {
        if (n != 5) assert(!smeg_mcu_peer_net(&s, 0x0e, config, n));
    }
    assert(!smeg_mcu_peer_net(&s, 0x0e, NULL, 5));
    assert(!smeg_mcu_peer_net(&s, 0x0d, config, 5));
    assert(s.net_count == 0);
    assert(smeg_mcu_peer_net(&s, 0x0e, config, 5));
    for (unsigned i = 0; i < 100; i++)
        assert(smeg_mcu_peer_net(&s, 0x0e, updated, 5));
    assert(s.net_count == 1); /* Latest state, no repeated stale menu events. */
    empty(frame);
    frame[91] ^= 1;
    memcpy(before, frame, sizeof(frame));
    assert(!smeg_mcu_peer_net_pending(&s, frame));
    assert(s.net_count == 1 && !memcmp(before, frame, sizeof(frame)));
    empty(frame);
    assert(smeg_mcu_peer_net_pending(&s, frame));
    assert(frame[1] == 1 && frame[2] == 2 && frame[3] == 0x0e && frame[4] == 5);
    assert(!memcmp(frame + 5, updated, 5));
    assert(smeg_mcu_crc_valid(frame + 2, 8) && smeg_mcu_crc_valid(frame, 90));
    assert(!s.net_count);
    /* Wrap the six-slot ring repeatedly and verify no pointer/index drift. */
    for (unsigned i = 0; i < 30; i++) {
        assert(smeg_mcu_peer_net(&s, 0x0e, config, 5));
        empty(frame);
        assert(smeg_mcu_peer_net_pending(&s, frame));
        assert(!memcmp(frame + 5, config, 5));
        assert(smeg_mcu_crc_valid(frame + 2, 8) && smeg_mcu_crc_valid(frame, 90));
    }
    /* These bits are original receiver inputs, not an invented menu flag. */
    assert((config[0] & 0x80) && (config[0] & 0x20));
    puts("BSI_INF_CFG NET0e/5: strict size, coalescing, CRC rejection, exact payload and ring wrap passed");
}
