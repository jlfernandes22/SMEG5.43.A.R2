/* Emulator-only ECU response state, never a physical vehicle transport. */
#ifndef SMEG_BENCH_ECU_H
#define SMEG_BENCH_ECU_H
#include "smeg_mcu_peer.h"

/* Assign the requested full-state option level into an explicit BSI260
 * fixture. Drain even when the fixture disappeared, preserving unrelated bits.
 * Repeated native commits and transport retries cannot invert the level. */
static inline int smeg_bench_body_apply(SmegMcuPeer *peer,
                                         uint8_t body_status[8], int valid)
{
    unsigned pending=peer->body_pending;
    unsigned level=peer->body_level&8;
    peer->body_pending=0;
    if(!pending||!valid||!body_status)return 0;
    uint8_t before=body_status[3];
    body_status[3]=(before&~8U)|level;
    return before!=body_status[3];
}

static inline unsigned smeg_bench_ecu_apply(SmegMcuPeer *peer,
                                            uint8_t payload[3][8], unsigned valid)
{
    uint32_t eco = smeg_mcu_peer_take_ecu_toggles(peer, 0);
    uint32_t parking = smeg_mcu_peer_take_ecu_toggles(peer, 1);
    unsigned changed = 0;
    unsigned status = payload[0][3] >> 6;
    if ((valid & 1) && (eco & 1) && (status == 1 || status == 2)) {
        payload[0][3] = (payload[0][3] & 0x3f) | ((3 - status) << 6);
        changed |= 1;
    }
    unsigned rear = payload[1][0] >> 5;
    unsigned front = (payload[1][0] >> 2) & 7;
    if ((valid & 2) && parking && rear == front &&
        (rear == 2 || rear == 4 || rear == 5)) {
        /* From standby the first request disables; subsequent toggles alternate
         * disabled/active. This bench response deliberately supplies a visual
         * request when activated so the real native parking UI can be tested. */
        unsigned next = rear;
        if (next == 5) { next = 2; parking--; }
        if (parking & 1) { next = next == 2 ? 4 : 2; }
        payload[1][0] = (payload[1][0] & 3) | (next << 5) | (next << 2);
        payload[1][5] = (payload[1][5] & ~2U) | (next == 4 ? 2 : 0);
        changed |= 2;
    }
    return changed;
}
#endif
