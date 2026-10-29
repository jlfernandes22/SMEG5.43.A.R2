#ifndef SMEG_BENCH_LED_H
#define SMEG_BENCH_LED_H
#include <stdint.h>

/* Native CDE_LED_PUSH CAN227/NET22: AAS D0bits7:6, STT D3bits3:2.
 * Raw1 is the steady disabled indicator; raw0 is the enabled/unlit indicator.
 * These are separate from sensor detection/overlay and hybrid-state messages. */
static inline int smeg_bench_led_sync(uint8_t led[8], const uint8_t eco[8],
                                      const uint8_t parking[8], unsigned valid)
{
    uint8_t old0 = led[0], old3 = led[3];
    unsigned eco_status = eco[3] >> 6;
    unsigned rear = parking[0] >> 5, front = (parking[0] >> 2) & 7;
    if ((valid & 1) && (eco_status == 1 || eco_status == 2)) {
        led[3] = (led[3] & ~0x0cU) | (eco_status == 2 ? 4 : 0);
    }
    if ((valid & 2) && rear == front &&
        (rear == 2 || rear == 4 || rear == 5)) {
        led[0] = (led[0] & ~0xc0U) | (rear == 2 ? 0x40 : 0);
    }
    return led[0] != old0 || led[3] != old3;
}
#endif
