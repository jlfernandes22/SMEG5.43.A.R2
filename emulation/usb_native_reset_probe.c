/* Local QEMU reset experiment. This is not a resource/firmware restore.
 * No application, MMI, USER_DATA, configuration, or NAND writer dependency.
 * Only fixed /bd0 paths are written. All streams close before USB removal.
 */
#ifndef SMEG_NATIVE_RESET_HOST_TEST
typedef unsigned int size_t;
typedef void FILE;
extern FILE *fopen(const char *, const char *);
extern size_t fread(void *, size_t, size_t, FILE *);
extern size_t fwrite(const void *, size_t, size_t, FILE *);
extern int fclose(FILE *);
extern int fflush(FILE *);
extern int ferror(FILE *);
extern int mkdir(const char *, int);
extern int printf(const char *, ...);
extern int taskDelay(int);
extern int sysClkRateGet(void);
extern void *iosDevFind(const char *, const char **);
#endif

#include "native_reset_contract.h"
#define RESET_SENTINEL "/bd0/RESET_PROBE/SENTINEL.TXT"
#define RESET_ARMED "/bd0/RESET_PROBE/ARMED"
#define RESET_STATUS RESET_ARMED "/STATUS.TXT"
#define RESET_SENTINEL_TEXT "SMEG_NATIVE_RESET_PROBE_V1\n"
#define RESET_STATUS_TEXT \
    "ARMED_WAITING_FOR_USB_REMOVAL\n" \
    "One use. This receipt is not proof that reset happened.\n" \
    "No resource, firmware, database or internal filesystem writes requested.\n"
#ifndef NATIVE_RESET_INVOKE
#define NATIVE_RESET_INVOKE() ((void (*)(void))NATIVE_RESET_ENTRY_ADDRESS)()
#endif

static unsigned reset_hash(const void *, unsigned);
static int reset_device_present(void);
static int reset_read_exact(const char *, const char *, unsigned);
static int reset_write_status(void);

/* ENTRY:YES enters .text offset zero. Keep the only public entry first. */
int smeg_native_reset_probe(void)
{
    unsigned i, absent = 0;
    int rate;
    printf("SMEG_NATIVE_RESET_BEGIN local-only native BSP reset; not a restore\n");
    for (i = 0; i < sizeof(native_reset_checks)/sizeof(native_reset_checks[0]); ++i) {
        const struct NativeResetCheck *c = &native_reset_checks[i];
        if (reset_hash((const void *)c->address, c->bytes) != c->hash) {
            printf("SMEG_NATIVE_RESET_ABORT fingerprint index=%u\n", i);
            return -1;
        }
    }
    if (!reset_device_present()) {
        printf("SMEG_NATIVE_RESET_ABORT USB not present before arming\n");
        return -2;
    }
    if (reset_read_exact(RESET_SENTINEL, RESET_SENTINEL_TEXT,
                         sizeof(RESET_SENTINEL_TEXT)-1)) {
        printf("SMEG_NATIVE_RESET_ABORT initial sentinel content/read/close\n");
        return -3;
    }
    rate = sysClkRateGet();
    if (rate < 1 || rate > 10000) {
        printf("SMEG_NATIVE_RESET_ABORT invalid clock rate=%d\n", rate);
        return -4;
    }
    if (!reset_device_present()) {
        printf("SMEG_NATIVE_RESET_ABORT USB disappeared before arming\n");
        return -5;
    }
    /* mkdir must succeed exclusively. Existing/failed guards are never reused,
     * deleted or overwritten, including after a previous timeout or failure. */
    if (mkdir(RESET_ARMED, 0777)) {
        printf("SMEG_NATIVE_RESET_ABORT one-use ARMED exists or mkdir failed\n");
        return -6;
    }
    if (reset_write_status() ||
        reset_read_exact(RESET_STATUS, RESET_STATUS_TEXT,
                         sizeof(RESET_STATUS_TEXT)-1)) {
        printf("SMEG_NATIVE_RESET_ABORT ARMED status write/readback/close\n");
        return -7;
    }
    printf("SMEG_NATIVE_RESET_ARMED remove USB; all streams closed; timeout=%u seconds\n",
           NATIVE_RESET_WAIT_SECONDS);
    for (i = 0; i < NATIVE_RESET_WAIT_SECONDS; ++i) {
        FILE *sentinel;
        if (taskDelay(rate)) {
            printf("SMEG_NATIVE_RESET_ABORT polling delay failed\n");
            return -8;
        }
        sentinel = fopen(RESET_SENTINEL, "rb");
        if (sentinel) {
            int bad = ferror(sentinel) != 0;
            if (fclose(sentinel)) bad = 1;
            if (bad) {
                printf("SMEG_NATIVE_RESET_ABORT polling stream error/close\n");
                return -9;
            }
            absent = 0;
        } else if (reset_device_present()) {
            /* I/O failure is not USB removal. Device registration is checked
             * independently, so repeated bad reads alone cannot request reset. */
            absent = 0;
        } else {
            ++absent;
        }
        if (absent >= NATIVE_RESET_ABSENT_CHECKS) {
            if (reset_device_present()) {
                printf("SMEG_NATIVE_RESET_ABORT USB returned before reset\n");
                return -10;
            }
            printf("SMEG_NATIVE_RESET_REQUEST original EmergencyReboot; USB absent checks=%u; no open streams\n",
                   absent);
            NATIVE_RESET_INVOKE();
            printf("SMEG_NATIVE_RESET_ABORT native reset unexpectedly returned\n");
            return -11;
        }
    }
    printf("SMEG_NATIVE_RESET_TIMEOUT no reset; one-use ARMED retained\n");
    return -12;
}

static unsigned reset_hash(const void *data, unsigned bytes)
{
    const unsigned char *p = data;
    unsigned h = 2166136261u;
    while (bytes--) h = (h ^ *p++) * 16777619u;
    return h;
}

static int reset_device_present(void)
{
    static const char device[] = "/bd0";
    const char *tail = device;
    void *found = iosDevFind(device, &tail);
    /* Original BSP isDevicePresent uses found && tail != input. Requiring the
     * complete /bd0 name also rejects a default or merely partial match. */
    return found && tail && tail != device && *tail == '\0';
}

static int reset_read_exact(const char *path, const char *expected, unsigned bytes)
{
    unsigned char buffer[192];
    unsigned i;
    size_t got;
    int bad;
    FILE *f;
    if (bytes >= sizeof(buffer)) return -1;
    f = fopen(path, "rb");
    if (!f) return -1;
    got = fread(buffer, 1, bytes+1, f);
    bad = ferror(f) || got != bytes;
    if (fclose(f)) bad = 1;
    if (!bad) for (i = 0; i < bytes; ++i)
        if (buffer[i] != (unsigned char)expected[i]) bad = 1;
    return bad ? -1 : 0;
}

static int reset_write_status(void)
{
    static const char text[] = RESET_STATUS_TEXT;
    FILE *f = fopen(RESET_STATUS, "wb");
    int bad;
    if (!f) return -1;
    bad = fwrite(text, 1, sizeof(text)-1, f) != sizeof(text)-1;
    if (ferror(f)) bad = 1;
    if (fflush(f)) bad = 1;
    if (fclose(f)) bad = 1;
    return bad ? -1 : 0;
}
