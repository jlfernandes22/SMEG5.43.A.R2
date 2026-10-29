/* Explicit virtual BSI notifications. No physical vehicle transport. */
#ifndef SMEG_BENCH_ALERT_H
#define SMEG_BENCH_ALERT_H
#include <stdint.h>
#include <string.h>
#include <limits.h>

#define SMEG_ALERT_NEUTRAL 0x7fff
#define SMEG_ALERT_REARM_NS 400000000LL
#define SMEG_ALERT_HOLD_NS 5000000000LL

typedef struct SmegBenchAlert {
    uint16_t current, pending;
    int64_t activate_ns, clear_ns;
    unsigned managed;
} SmegBenchAlert;

static inline void smeg_bench_alert_reset(SmegBenchAlert *s)
{
    memset(s, 0, sizeof(*s));
    s->current = s->pending = SMEG_ALERT_NEUTRAL;
}

static inline int smeg_bench_alert_request(SmegBenchAlert *s,
                                          unsigned pointer, int64_t now)
{
    /* Original db_alerts pointers: ECO on/off and ordinary ESP on/off.
     * BSI_CDE_PTR_MESSAGE carries a level. A neutral interval rearms a later
     * identical notification without repeatedly reopening a dismissed one. */
    if (pointer != 544 && pointer != 545 && pointer != 313 && pointer != 314) {
        return 0;
    }
    s->managed = 1;
    s->current = SMEG_ALERT_NEUTRAL;
    s->pending = pointer;
    s->activate_ns = now + SMEG_ALERT_REARM_NS;
    s->clear_ns = 0;
    return 1;
}

static inline int smeg_bench_alert_advance(SmegBenchAlert *s, int64_t now,
                                          uint8_t payload[8])
{
    uint8_t next[8] = {0};
    if (!s->managed) {
        return 0;
    }
    if (s->activate_ns && now >= s->activate_ns) {
        s->current = s->pending;
        s->pending = SMEG_ALERT_NEUTRAL;
        s->activate_ns = 0;
        s->clear_ns = now + SMEG_ALERT_HOLD_NS;
    } else if (s->clear_ns && now >= s->clear_ns) {
        s->current = SMEG_ALERT_NEUTRAL;
        s->clear_ns = 0;
    }
    next[0] = (s->current >> 8) & 0x7f;
    next[1] = s->current;
    next[2] = s->current == SMEG_ALERT_NEUTRAL ? 0 : 1;
    if (!memcmp(payload, next, 8)) {
        return 0;
    }
    memcpy(payload, next, 8);
    return 1;
}

static inline int64_t smeg_bench_alert_deadline(const SmegBenchAlert *s)
{
    if (!s->managed) {
        return INT64_MAX;
    }
    return s->activate_ns ? s->activate_ns :
        (s->clear_ns ? s->clear_ns : INT64_MAX);
}
#endif
