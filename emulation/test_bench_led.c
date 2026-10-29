#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "emulation/smeg_bench_led.h"
int main(void)
{
    const uint8_t original[8] = {0xaf,0x13,0x72,0xb6,0xc9,0xdf,0x12,0x34};
    uint8_t led[8], want[8], eco[8] = {0}, parking[8] = {0};
    for (unsigned e = 0; e < 4; e++) {
        for (unsigned p = 0; p < 8; p++) {
            for (unsigned valid = 0; valid < 4; valid++) {
                memcpy(led, original, 8); memcpy(want, original, 8);
                eco[3] = e << 6; parking[0] = (p << 5) | (p << 2) | 3;
                if ((valid & 1) && (e == 1 || e == 2)) {
                    want[3] = (want[3] & ~0x0cU) | (e == 2 ? 4 : 0);
                }
                if ((valid & 2) && (p == 2 || p == 4 || p == 5)) {
                    want[0] = (want[0] & ~0xc0U) | (p == 2 ? 0x40 : 0);
                }
                int changed = smeg_bench_led_sync(led, eco, parking, valid);
                assert(!memcmp(led, want, 8));
                assert(changed == (memcmp(original, want, 8) != 0));
                assert(!smeg_bench_led_sync(led, eco, parking, valid));
            }
        }
    }
    memcpy(led, original, 8); eco[3] = 0; parking[0] = (2 << 5) | (4 << 2);
    assert(!smeg_bench_led_sync(led, eco, parking, 3));
    assert(!memcmp(led, original, 8));
    puts("Native AAS/STT LED sync: exact disabled/enabled states, unsupported/mismatched inputs, validity, preserved bits and idempotence passed");
}
