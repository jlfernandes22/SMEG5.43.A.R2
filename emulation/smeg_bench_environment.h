/* Native BSI environment fixtures. No host/physical CAN access. */
#ifndef SMEG_BENCH_ENVIRONMENT_H
#define SMEG_BENCH_ENVIRONMENT_H
#include <stdint.h>
#include <time.h>

/* Verified in DONNEES_BSI_LENTES_3 constructor/GetDateTime:
 * CAN276, local13, len5, period1000ms; years are relative to2000.
 * Preserve flag bits not owned by the civil date/time fields. */
static inline int smeg_bench_date(uint8_t out[5], const struct tm *tm)
{
    static const int days[] = {31,28,31,30,31,30,31,31,30,31,30,31};
    int year = tm->tm_year + 1900;
    if (year < 2000 || year > 2125 || tm->tm_mon < 0 || tm->tm_mon > 11 ||
        tm->tm_hour < 0 || tm->tm_hour > 23 || tm->tm_min < 0 || tm->tm_min > 59)
        return 0;
    int maxday = days[tm->tm_mon] + (tm->tm_mon == 1 && year % 4 == 0 &&
                                          (year % 100 != 0 || year % 400 == 0));
    if (tm->tm_mday < 1 || tm->tm_mday > maxday) return 0;
    out[0] = (out[0] & 0x80) | (year - 2000);
    out[1] = (out[1] & 0xf0) | (tm->tm_mon + 1);
    out[2] = (out[2] & 0xc0) | tm->tm_mday;
    out[3] = (out[3] & 0xe0) | tm->tm_hour;
    out[4] = (out[4] & 0xc0) | tm->tm_min;
    return 1;
}
/* CAN0f6 D6: 0..250 valid, 255 unknown; raw = 2*(Celsius+40).
 * Setting D6 must never clear service/power-state bits elsewhere. */
static inline int smeg_bench_temperature(uint8_t out[8], unsigned raw)
{
    if (raw > 250 && raw != 255) return 0;
    out[6] = raw;
    return 1;
}
#endif
