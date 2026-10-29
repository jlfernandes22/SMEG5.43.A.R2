/* QEMU-only native single-flag experiment. No physical deployment approval.
 * Reuse the exporter's first text entry and backup-before-set hook; the hook's
 * historic name is only a local preprocessor alias, not a Web_active operation.
 * This module never installs a database, theme resource, firmware or RAM patch.
 */
#define SMEG_EMULATOR_ONLY_SET_WEB 1
#define smeg_emulator_set_web smeg_emulator_enable_warmlight
#include "usb_backup_readonly.c"
#undef smeg_emulator_set_web
#undef SMEG_EMULATOR_ONLY_SET_WEB

typedef struct { unsigned int words[32]; } WarmNativeObject;
#include "usb_warmlight_api_fingerprints.h"

static unsigned int warm_fingerprint(const void *ptr, unsigned int count)
{
    const unsigned char *p = ptr;
    unsigned int h = 2166136261u;
    while (count--) h = (h ^ *p++) * 16777619u;
    return h;
}

static int warm_file_hash(const char *path, unsigned int *bytes,
                          unsigned int *hash)
{
    FILE *f = fopen(path, "rb");
    size_t n, i;
    int bad;
    if (!f) return -1;
    *bytes = 0; *hash = 2166136261u;
    while ((n = fread(buffer, 1, sizeof(buffer), f)) != 0) {
        *bytes += n;
        for (i = 0; i < n; ++i) *hash = (*hash ^ buffer[i]) * 16777619u;
    }
    bad = ferror(f);
    if (fclose(f) != 0) bad = 1;
    return bad ? -1 : 0;
}

int smeg_emulator_enable_warmlight(void)
{
    WarmNativeObject section, name, old, request, verify;
    void *(*up_instance)(void);
    int (*up_get)(void *, const void *, const void *, void *);
    int (*up_set)(void *, const void *);
    void (*string_ctor)(void *, const char *, int, int, int);
    void (*keys_ctor)(void *);
    int (*key_bool)(const void *, const void *, const void *, unsigned char *, int);
    int (*add_bool)(void *, const void *, const void *, int, int);
    int (*key_count)(const void *);
    void (*keys_dtor)(void *);
    void (*string_dtor)(void *);
    const void *functions[10];
    void *up;
    unsigned char before = 255, after = 255;
    unsigned int i, bytes1, bytes2, hash1, hash2;
    int status = -1, initialized = 0;
    FILE *log = fopen("/bd0/SMEG_BACKUP/warmlight-change.txt", "wb");
    if (!log) return -30;
    fprintf(log, "EXPERIMENTAL QEMU-ONLY display.Harm_11.0 ENABLE\n");
    /* An unmodified complete export precedes this hook. Also read the saved
     * up_config pair back from USB and compare it with its current source.
     * This is an I/O guard, not a transactionally atomic database snapshot.
     */
    for (i = 0; i < 2; ++i) {
        const char *src = i ? "/USER_DATA/user_data/sqlite/up_config.sqlite.inf"
                            : "/USER_DATA/user_data/sqlite/up_config.sqlite";
        const char *dst = i ? "/bd0/SMEG_BACKUP/up_config.sqlite.inf"
                            : "/bd0/SMEG_BACKUP/up_config.sqlite";
        if (warm_file_hash(src, &bytes1, &hash1) != 0 ||
            warm_file_hash(dst, &bytes2, &hash2) != 0 || bytes1 == 0 ||
            bytes1 != bytes2 || hash1 != hash2) {
            fprintf(log, "ABORT original up_config pair backup missing, changed or unreadable\n");
            status = -31; goto done;
        }
        fprintf(log, "BACKUP_VERIFIED %s bytes=%u fnv1a=%08x\n", dst, bytes1, hash1);
    }
    for (i = 0; i < sizeof(warm_api_checks)/sizeof(warm_api_checks[0]); ++i) {
        functions[i] = (const void *)warm_api_checks[i].address;
        if (warm_fingerprint(functions[i], warm_api_checks[i].bytes) !=
            warm_api_checks[i].hash) {
            fprintf(log, "ABORT AUDIO_BT_256_5.43 API fingerprint mismatch index=%u; no setter called\n", i);
            status = -32; goto done;
        }
    }
    fprintf(log, "VERIFIED_API_PROFILE AUDIO_BT_256_5.43 functions=%u\n", i);
    up_instance = (void *(*)(void))functions[0];
    up_get = (int (*)(void *, const void *, const void *, void *))functions[1];
    up_set = (int (*)(void *, const void *))functions[2];
    string_ctor = (void (*)(void *, const char *, int, int, int))functions[3];
    keys_ctor = (void (*)(void *))functions[4];
    key_bool = (int (*)(const void *, const void *, const void *, unsigned char *, int))functions[5];
    add_bool = (int (*)(void *, const void *, const void *, int, int))functions[6];
    key_count = (int (*)(const void *))functions[7];
    keys_dtor = (void (*)(void *))functions[8];
    string_dtor = (void (*)(void *))functions[9];
    up = up_instance();
    if (!up) { fprintf(log, "ABORT UP instance unavailable\n"); status = -33; goto done; }
    string_ctor(&section, "display", -1, 0, 1);
    string_ctor(&name, "Harm_11", -1, 0, 1);
    keys_ctor(&old); keys_ctor(&request); keys_ctor(&verify); initialized = 1;
    {
        int get_status = up_get(up, &section, &name, &old);
        int count = key_count(&old);
        int bool_status = key_bool(&old, &section, &name, &before, 0);
        fprintf(log, "GET status=%d keys=%d bool_status=%d value=%u\n",
                get_status, count, bool_status, (unsigned int)before);
        if (get_status == -1 || count != 1 || bool_status != 0 || before > 1) {
            fprintf(log, "ABORT exact existing bool key not readable\n");
            status = -34; goto done;
        }
    }
    fprintf(log, "BEFORE display.Harm_11.0=%u\n", (unsigned int)before);
    if (before == 1) {
        fprintf(log, "UNCHANGED already enabled; setter not called\n");
        status = 0; goto done;
    }
    if (!add_bool(&request, &section, &name, 1, 0) || key_count(&request) != 1) {
        fprintf(log, "ABORT one-key request validation failed\n");
        status = -35; goto done;
    }
    status = up_set(up, &request);
    fprintf(log, "NATIVE_SET_CONFIG_KEYS_IMMEDIATE status=%d request_keys=%d\n",
            status, key_count(&request));
    if (status == -1 || up_get(up, &section, &name, &verify) == -1 ||
        key_count(&verify) != 1 ||
        key_bool(&verify, &section, &name, &after, 0) != 0 || after != 1) {
        fprintf(log, "FAILED native readback; original complete file is on USB; no rollback or reboot attempted\n");
        status = -36; goto done;
    }
    fprintf(log, "AFTER display.Harm_11.0=%u\nFINISHED native one-key save; no automatic reboot\n",
            (unsigned int)after);
    status = 0;
done:
    printf("SMEG_SANDBOX_WARMLIGHT_RESULT status=%d before=%u after=%u\n",
           status, (unsigned int)before, (unsigned int)after);
    if (initialized) {
        keys_dtor(&verify); keys_dtor(&request); keys_dtor(&old);
        string_dtor(&name); string_dtor(&section);
    }
    if (fflush(log) != 0) status = -37;
    if (fclose(log) != 0) status = -37;
    return status;
}
