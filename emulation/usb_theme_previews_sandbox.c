/* QEMU-only final theme assets: add missing JPEG previews and request only
 * the six additional theme availability flags using the existing native API.
 * Existing previews, selected theme, binaries and unrelated preferences are
 * never overwritten by this helper.
 */
#define SMEG_EXTRA_THEME_PREVIEWS 1
#include "usb_extra_theme_flags_sandbox.c"
#include "theme_preview_contract.h"
#include "theme_preview_fs_contract.h"
extern int errnoGet(void);
extern void *opendir(const char *);
extern int closedir(void *);

static int smeg_copy_new_theme_previews(void)
{
    unsigned index;
    FILE *log = fopen("/bd0/SMEG_BACKUP/theme-previews.txt", "wb");
    int status = -70;
    void *volume = 0;
    int original_read_only = -1, mount_changed = 0;
    void *(*volume_get)(const char *, void *) = (void *(*)(const char *, void *))preview_fs_api[0].address;
    int (*read_only_set)(const char *, int) = (int (*)(const char *, int))preview_fs_api[1].address;
    if (!log) return status;
    {
        static const char *dirs[] = {"/SYSTEM", "/SYSTEM/Data_Base", "/SYSTEM/Data_Base/BOARDFS",
            "/SYSTEM/Data_Base/BOARDFS/GUI_STYLE", "/SYSTEM/Data_Base/BOARDFS/GUI_STYLE/GUIS_RESSOURCES"};
        unsigned d;
        for (d = 0; d < sizeof(dirs)/sizeof(dirs[0]); ++d) {
            void *dir = opendir(dirs[d]);
            int saved_errno = errnoGet();
            fprintf(log, "PATH_PROBE %s opened=%d errno=%08x\n", dirs[d], dir != 0, saved_errno);
            if (dir) closedir(dir);
        }
        fflush(log);
    }
    for (index = 0; index < 2; ++index) {
        if (fingerprint((const void *)preview_fs_api[index].address, 64) != preview_fs_api[index].hash) {
            status = -82; goto done;
        }
    }
    volume = volume_get("/SYSTEM", 0);
    if (!volume) { status = -83; goto done; }
    /* Offset established by the exact guarded native setter at 0x46e568. */
    original_read_only = (int)((const unsigned *)volume)[0x340/4];
    fprintf(log, "SYSTEM original_read_only=%d\n", original_read_only);
    if (original_read_only != 0 && original_read_only != 1) { status = -84; goto done; }
    if (original_read_only) {
        if (read_only_set("/SYSTEM", 0) != 0) { status = -85; goto done; }
        mount_changed = 1;
        fprintf(log, "SYSTEM temporarily writable through native filesystem API\n");
    }
    for (index = 0; index < 6; ++index) {
        const struct ThemePreview *p = &theme_previews[index];
        FILE *in, *out;
        unsigned count = 0, hash = 2166136261u;
        size_t n, j;
        in = fopen(p->destination, "rb");
        if (in) {
            while ((n = fread(buffer, 1, sizeof(buffer), in)) != 0) {
                for (j = 0; j < n; ++j) hash = (hash ^ buffer[j]) * 16777619u;
                count += n;
            }
            status = ferror(in) ? -71 : 0;
            if (fclose(in) != 0) status = -71;
            if (status || count != p->bytes || hash != p->hash) {
                fprintf(log, "ABORT existing preview differs; not overwritten: %s\n", p->destination);
                status = -72; goto done;
            }
            fprintf(log, "ALREADY_IDENTICAL %s\n", p->destination);
            continue;
        }
        if (mkdir(p->directory, 0777) != 0) {
            int saved_errno = errnoGet();
            fprintf(log, "ABORT mkdir failed errno=%08x path=%s\n", saved_errno, p->directory);
            status = -73; goto done;
        }
        in = fopen(p->source, "rb");
        if (!in) { status = -74; goto done; }
        out = fopen(p->destination, "wb");
        if (!out) { fclose(in); status = -75; goto done; }
        status = 0;
        while ((n = fread(buffer, 1, sizeof(buffer), in)) != 0) {
            if (fwrite(buffer, 1, n, out) != n) { status = -76; break; }
            count += n;
            for (j = 0; j < n; ++j) hash = (hash ^ buffer[j]) * 16777619u;
        }
        if (ferror(in) || count != p->bytes || hash != p->hash) status = -77;
        if (fclose(in) != 0 || fflush(out) != 0) status = -78;
        if (fclose(out) != 0) status = -78;
        if (status) goto done;
        in = fopen(p->destination, "rb");
        if (!in) { status = -79; goto done; }
        count = 0; hash = 2166136261u;
        while ((n = fread(buffer, 1, sizeof(buffer), in)) != 0) {
            count += n;
            for (j = 0; j < n; ++j) hash = (hash ^ buffer[j]) * 16777619u;
        }
        if (ferror(in) || count != p->bytes || hash != p->hash) status = -80;
        if (fclose(in) != 0) status = -80;
        if (status) goto done;
        fprintf(log, "ADDED_AND_VERIFIED %s bytes=%u\n", p->destination, count);
        fflush(log);
    }
    status = 0;
    fprintf(log, "FINISHED six native theme previews; unrelated files not replaced\n");
done:
    if (mount_changed) {
        int restored = read_only_set("/SYSTEM", original_read_only);
        fprintf(log, "SYSTEM restore_read_only status=%d observed=%u\n", restored,
                ((const unsigned *)volume)[0x340/4]);
        if (restored != 0 || (int)((const unsigned *)volume)[0x340/4] != original_read_only) status = -86;
    }
    fprintf(log, "PREVIEW_RESULT status=%d\n", status);
    if (fflush(log) != 0) status = -81;
    if (fclose(log) != 0) status = -81;
    return status;
}
