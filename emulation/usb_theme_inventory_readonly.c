/* Read-only native theme-bank inventory. Export existing DBs first; write
 * inventory and small header copies only to /bd0. No settings or flash writes.
 */
#define SMEG_EMULATOR_ONLY_SET_WEB 1
#define smeg_emulator_set_web smeg_read_theme_inventory
#include "usb_backup_readonly.c"
#undef smeg_emulator_set_web
#undef SMEG_EMULATOR_ONLY_SET_WEB

#include "usb_warmlight_api_fingerprints.h"

static unsigned int inventory_hash(const void *ptr, unsigned count)
{
    const unsigned char *p = ptr;
    unsigned int h = 2166136261u;
    while (count--) h = (h ^ *p++) * 16777619u;
    return h;
}

static unsigned int inventory_be32(const unsigned char *p)
{
    return ((unsigned int)p[0] << 24) | ((unsigned int)p[1] << 16) |
           ((unsigned int)p[2] << 8) | p[3];
}

static int inventory_save(const char *path, const void *data, unsigned bytes)
{
    FILE *f = fopen(path, "wb");
    int ok;
    if (!f) return -1;
    ok = fwrite(data, 1, bytes, f) == bytes;
    if (fflush(f) != 0) ok = 0;
    if (fclose(f) != 0) ok = 0;
    return ok ? 0 : -1;
}

int smeg_read_theme_inventory(void)
{
    int (*read_pre)(int, void *);
    int (*read_big)(int, void *);
    int (*read_entry)(int, int, void *);
    /* The native API copies the complete header, up to one 2048-byte page. */
    unsigned char pre[168], big[2048], entry[216];
    unsigned int bank, i, total = 0;
    int result = -1;
    char path[120], name[197];
    FILE *log = fopen("/bd0/SMEG_BACKUP/theme-inventory.txt", "wb");
    if (!log) return -40;
    fprintf(log, "READ-ONLY native theme inventory; no configuration setter or flash writer\n");
    for (i = 0; i < 3; ++i) {
        if (inventory_hash((const void *)warm_api_checks[i].address,
                           warm_api_checks[i].bytes) != warm_api_checks[i].hash) {
            fprintf(log, "ABORT exact AUDIO_BT_256 BSP reader mismatch %u\n", i);
            result = -41; goto done;
        }
    }
    read_pre = (int (*)(int, void *))warm_api_checks[0].address;
    read_big = (int (*)(int, void *))warm_api_checks[1].address;
    read_entry = (int (*)(int, int, void *))warm_api_checks[2].address;
    fprintf(log, "VERIFIED_BSP_READERS count=3\n");
    for (bank = 1; bank <= 6; ++bank) {
        unsigned int count;
        int status = read_pre((int)bank, pre);
        fprintf(log, "BANK %u preheader_status=%d\n", bank, status);
        if (status != 0) continue;
        snprintf(path, sizeof(path), "/bd0/SMEG_BACKUP/theme-bank%02u-preheader.bin", bank);
        if (inventory_save(path, pre, sizeof(pre)) != 0) { result = -42; goto done; }
        status = read_big((int)bank, big);
        fprintf(log, "BANK %u big_header_status=%d\n", bank, status);
        if (status != 0) continue;
        count = inventory_be32(big + 32);
        fprintf(log, "BANK %u entry_count=%u\n", bank, count);
        if (count > 9) {
            fprintf(log, "ABORT implausible directory count; no entry scan\n");
            result = -43; goto done;
        }
        snprintf(path, sizeof(path), "/bd0/SMEG_BACKUP/theme-bank%02u-directory.bin", bank);
        if (inventory_save(path, big, 36) != 0) { result = -44; goto done; }
        for (i = 1; i <= count; ++i) {
            unsigned int j;
            status = read_entry((int)bank, (int)i, entry);
            fprintf(log, "BANK %u entry=%u status=%d\n", bank, i, status);
            if (status != 0) continue;
            for (j = 0; j < 196; ++j) {
                unsigned char v = entry[j];
                name[j] = v == 0 ? 0 : (v >= 32 && v <= 126 ? (char)v : '?');
            }
            name[196] = 0;
            fprintf(log, "THEME bank=%u entry=%u name=%s HMI_slot=%u payload_page=%u payload_bytes=%u CRC32=%08x\n",
                    bank, i, name, inventory_be32(entry + 200), inventory_be32(entry + 204),
                    inventory_be32(entry + 208), inventory_be32(entry + 212));
            snprintf(path, sizeof(path), "/bd0/SMEG_BACKUP/theme-bank%02u-entry%02u.bin", bank, i);
            if (inventory_save(path, entry, sizeof(entry)) != 0) { result = -45; goto done; }
            ++total;
        }
    }
    fprintf(log, "FINISHED read-only theme inventory; readable_entries=%u\n", total);
    result = 0;
done:
    printf("SMEG_THEME_INVENTORY_RESULT status=%d\n", result);
    if (fflush(log) != 0) result = -46;
    if (fclose(log) != 0) result = -46;
    return result;
}
