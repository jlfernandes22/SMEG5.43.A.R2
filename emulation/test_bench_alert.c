#include <assert.h>
#include <stdio.h>
#include "emulation/smeg_bench_alert.h"

static unsigned pointer(const uint8_t p[8]) { return (p[0] << 8) | p[1]; }
int main(void)
{
    SmegBenchAlert s, before;
    uint8_t p[8] = {0xaa,0xbb,0xcc,0xdd,1,2,3,4};
    smeg_bench_alert_reset(&s);
    assert(!smeg_bench_alert_advance(&s, 0, p) && p[0] == 0xaa);
    before = s;
    assert(!smeg_bench_alert_request(&s, 42, 0));
    assert(!memcmp(&s, &before, sizeof(s)));
    const unsigned ids[] = {545,544,314,313};
    int64_t now = 10;
    for (unsigned n = 0; n < 4; n++) {
        assert(smeg_bench_alert_request(&s, ids[n], now));
        smeg_bench_alert_advance(&s, now, p);
        assert(pointer(p) == SMEG_ALERT_NEUTRAL && p[2] == 0);
        assert(smeg_bench_alert_deadline(&s) == now + SMEG_ALERT_REARM_NS);
        assert(!smeg_bench_alert_advance(&s, now + SMEG_ALERT_REARM_NS - 1, p));
        now += SMEG_ALERT_REARM_NS;
        assert(smeg_bench_alert_advance(&s, now, p));
        assert(pointer(p) == ids[n] && p[2] == 1);
        for (unsigned i = 3; i < 8; i++) { assert(p[i] == 0); }
        assert(!smeg_bench_alert_advance(&s, now + SMEG_ALERT_HOLD_NS - 1, p));
        now += SMEG_ALERT_HOLD_NS;
        assert(smeg_bench_alert_advance(&s, now, p));
        assert(pointer(p) == SMEG_ALERT_NEUTRAL && !p[2]);
        assert(smeg_bench_alert_deadline(&s) == INT64_MAX);
    }
    /* Rearm an identical request and supersede a queued request safely. */
    assert(smeg_bench_alert_request(&s, 545, now));
    assert(smeg_bench_alert_request(&s, 314, now + 1));
    smeg_bench_alert_advance(&s, now + SMEG_ALERT_REARM_NS, p);
    assert(pointer(p) == SMEG_ALERT_NEUTRAL);
    smeg_bench_alert_advance(&s, now + SMEG_ALERT_REARM_NS + 1, p);
    assert(pointer(p) == 314);
    assert(smeg_bench_alert_request(&s, 314, now + SMEG_ALERT_REARM_NS + 2));
    smeg_bench_alert_advance(&s, now + SMEG_ALERT_REARM_NS + 2, p);
    assert(pointer(p) == SMEG_ALERT_NEUTRAL);
    smeg_bench_alert_reset(&s);
    assert(!s.managed && !s.activate_ns && !s.clear_ns);
    puts("Virtual native alerts: exact whitelist, neutral rearm, hold/clear, replacement, repeat, reset and payload integrity passed");
}
