/* Emulator-only counterfactual: six missing theme availability flags, with
 * original application, theme banks, names and mappings left untouched.
 * Never stage this probe on a physical USB.
 */
#ifndef SMEG_BACKUP_INCLUDED_EXTERNALLY
#define SMEG_EMULATOR_ONLY_SET_WEB 1
#define smeg_emulator_set_web smeg_emulator_extra_theme_flags
#include "usb_backup_readonly.c"
#undef smeg_emulator_set_web
#undef SMEG_EMULATOR_ONLY_SET_WEB
#endif

typedef struct { unsigned int words[32]; } NativeObject;
#include "usb_warmlight_api_fingerprints.h"
#ifdef SMEG_EXTRA_THEME_PREVIEWS
static int smeg_copy_new_theme_previews(void);
#endif

static unsigned int fingerprint(const void *ptr, unsigned count)
{
    const unsigned char *p = ptr;
    unsigned int h = 2166136261u;
    while (count--) h = (h ^ *p++) * 16777619u;
    return h;
}

int smeg_emulator_extra_theme_flags(void)
{
    static const char *names[] = {"Harm_1", "Harm_2", "Harm_3",
                                  "Harm_4", "Harm_7", "Harm_8"};
    NativeObject section, name, value, request;
    void *functions[10], *up;
    void *(*instance)(void);
    int (*get)(void *, const void *, const void *, void *);
    int (*set)(void *, const void *);
    void (*string_ctor)(void *, const char *, int, int, int);
    void (*keys_ctor)(void *);
    int (*get_bool)(const void *, const void *, const void *, unsigned char *, int);
    int (*add_bool)(void *, const void *, const void *, int, int);
    int (*count)(const void *);
    void (*keys_dtor)(void *), (*string_dtor)(void *);
    unsigned int i, requested = 0;
    int result = -1, initialized = 0;
    FILE *log = fopen("/bd0/SMEG_BACKUP/theme-flags.txt", "wb");
    if (!log) return -30;
    fprintf(log, "EMULATOR ONLY: six availability flags; no names, mappings, resources or code changes\n");
    for (i = 0; i < 10; ++i) {
        functions[i] = (void *)warm_api_checks[i].address;
        if (fingerprint(functions[i], warm_api_checks[i].bytes) != warm_api_checks[i].hash) {
            fprintf(log, "ABORT original AUDIO_BT_256 API fingerprint mismatch %u\n", i);
            result = -31; goto done;
        }
    }
    instance = (void *(*)(void))functions[0];
    get = (int (*)(void *, const void *, const void *, void *))functions[1];
    set = (int (*)(void *, const void *))functions[2];
    string_ctor = (void (*)(void *, const char *, int, int, int))functions[3];
    keys_ctor = (void (*)(void *))functions[4];
    get_bool = (int (*)(const void *, const void *, const void *, unsigned char *, int))functions[5];
    add_bool = (int (*)(void *, const void *, const void *, int, int))functions[6];
    count = (int (*)(const void *))functions[7];
    keys_dtor = (void (*)(void *))functions[8];
    string_dtor = (void (*)(void *))functions[9];
    up = instance();
    if (!up) { result = -32; goto done; }
    string_ctor(&section, "display", -1, 0, 1);
    keys_ctor(&request); initialized = 1;
    for (i = 0; i < 6; ++i) {
        unsigned char before = 255;
        int valid;
        string_ctor(&name, names[i], -1, 0, 1);
        keys_ctor(&value);
        valid = get(up, &section, &name, &value) != -1 && count(&value) == 1 &&
                get_bool(&value, &section, &name, &before, 0) == 0 && before <= 1;
        fprintf(log, "BEFORE display.%s.0=%u valid=%d\n", names[i], (unsigned)before, valid);
        if (valid && before == 0) {
            valid = add_bool(&request, &section, &name, 1, 0) != 0;
            ++requested;
            valid = valid && count(&request) == (int)requested;
        }
        keys_dtor(&value); string_dtor(&name);
        if (!valid) { result = -33; goto done; }
    }
    if (requested) {
        result = set(up, &request);
        fprintf(log, "NATIVE_SET_CONFIG_KEYS_IMMEDIATE status=%d request_keys=%u\n", result, requested);
        if (result == -1) goto done;
    }
    for (i = 0; i < 6; ++i) {
        unsigned char after = 255;
        int valid;
        string_ctor(&name, names[i], -1, 0, 1); keys_ctor(&value);
        valid = get(up, &section, &name, &value) != -1 && count(&value) == 1 &&
                get_bool(&value, &section, &name, &after, 0) == 0 && after == 1;
        fprintf(log, "AFTER display.%s.0=%u valid=%d\n", names[i], (unsigned)after, valid);
        keys_dtor(&value); string_dtor(&name);
        if (!valid) { result = -34; goto done; }
    }
    fprintf(log, "FINISHED six flags; names mappings and resource banks unchanged\n");
    result = 0;
done:
#ifdef SMEG_EXTRA_THEME_PREVIEWS
    if (result == 0) result = smeg_copy_new_theme_previews();
#endif
    if (initialized) { keys_dtor(&request); string_dtor(&section); }
    printf("SMEG_EXTRA_THEME_FLAGS_RESULT status=%d\n", result);
    if (fflush(log) != 0) result = -35;
    if (fclose(log) != 0) result = -35;
    return result;
}
