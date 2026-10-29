/* Experimental maintenance module; physical execution remains unverified.
 * Input files are opened only with "rb"; output paths are fixed to /bd0.
 * No NAND write API, SQL, firmware patch, shell, network, or arbitrary path input.
 * A nonempty destination is never reused. Host must validate gzip and SQLite.
 */
typedef unsigned int size_t;
typedef unsigned int u32;
typedef void FILE;
extern FILE *fopen(const char *, const char *);
extern size_t fread(void *, size_t, size_t, FILE *);
extern size_t fwrite(const void *, size_t, size_t, FILE *);
extern int fclose(FILE *);
extern int fflush(FILE *);
extern int ferror(FILE *);
extern int mkdir(const char *, int);
extern int printf(const char *, ...);
extern int fprintf(FILE *, const char *, ...);
extern int snprintf(char *, size_t, const char *, ...);
extern int taskDelay(int);
extern int sysClkRateGet(void);

static unsigned char buffer[1024];
static const char *names[] = {
    "up_config.sqlite", "config_options.sqlite", "up_common.sqlite",
    "up_user.sqlite", "up_user_hmi.sqlite", "diag_zi.sqlite",
    "db_manager.sqlite", "config.sqlite", "connectivity.sqlite",
    "desktopServices.sqlite", "browser.sqlite", "versions.sqlite",
    "version_history.sqlite"
};
#ifdef SMEG_EMULATOR_ONLY_SET_WEB
int smeg_emulator_set_web(void);
#endif
#ifdef SMEG_RUNTIME_AND_WEB
int smeg_usb_runtime_gates(void);
#endif
#ifdef SMEG_EMULATOR_ONLY_SET_PORTAL
int smeg_emulator_set_portal(void);
#endif
#ifdef SMEG_EMULATOR_ONLY_NETWORK_CACHE
int smeg_emulator_network_cache(void);
int smeg_emulator_network_finish(void);
#endif
static void write_status(unsigned, unsigned, unsigned, const char *);

/* Keep this first in .text: VxWorks relocatable ENTRY:YES enters text offset0. */
int smeg_usb_readonly_backup(void)
{
    FILE *report;
    char source[160], target[160];
    unsigned n, suffix, copied = 0, failed = 0;
    /* Boot-time USB can mount before the user partition. Wait boundedly for
     * its existing DB, using read-only opens, before claiming an export. */
    {
        unsigned attempt;
        for (attempt=0;attempt<300;++attempt) {
            FILE *ready=fopen("/USER_DATA/user_data/sqlite/up_config.sqlite","rb");
            if(ready) {fclose(ready);break;}
            { int ticks=sysClkRateGet()/10;taskDelay(ticks>0?ticks:1); }
        }
        if(attempt==300) {printf("SMEG_RO_BACKUP_ABORT: source partition not ready\n");return -4;}
    }
    if (mkdir("/bd0/SMEG_BACKUP", 0777) != 0) {
        printf("SMEG_RO_BACKUP_ABORT: destination already exists or cannot be created\n");
        return -1;
    }
    report = fopen("/bd0/SMEG_BACKUP/report.txt", "wb");
    if (!report) return -2;
    fprintf(report, "SMEG experimental read-only configuration export\n");
    fflush(report);
    write_status(0, 0, 0, "RUNNING");
    for (n = 0; n < sizeof(names)/sizeof(names[0]); ++n) {
        for (suffix = 0; suffix < 2; ++suffix) {
            FILE *in, *out;
            u32 hash = 2166136261u, second = 2166136261u;
            u32 bytes = 0, bytes2 = 0;
            size_t got, i;
            int bad = 0;
            snprintf(source, sizeof(source), "/USER_DATA/user_data/sqlite/%s%s", names[n], suffix ? ".inf" : "");
            snprintf(target, sizeof(target), "/bd0/SMEG_BACKUP/%s%s", names[n], suffix ? ".inf" : "");
            in = fopen(source, "rb");
            if (!in) {
                fprintf(report, "MISSING %s\n", source);
                if (n < 5 && !suffix) ++failed;
                fflush(report);
                write_status(n*2+suffix+1, copied, failed, "RUNNING");
                continue;
            }
            out = fopen(target, "wb");
            if (!out) {
                fclose(in); ++failed;
                fprintf(report, "OUTPUT_ERROR %s\n", target);
                fflush(report);
                write_status(n*2+suffix+1, copied, failed, "RUNNING");
                continue;
            }
            while ((got = fread(buffer, 1, sizeof(buffer), in)) != 0) {
                if (fwrite(buffer, 1, got, out) != got) { bad = 1; break; }
                for (i = 0; i < got; ++i) hash = (hash ^ buffer[i]) * 16777619u;
                bytes += got;
            }
            if (ferror(in)) bad = 1;
            if (fflush(out) != 0) bad = 1;
            if (fclose(out) != 0) bad = 1;
            fclose(in);
            /* Detect normal concurrent application writes; do not claim a
             * consistent backup merely because the first read succeeded. */
            in = fopen(source, "rb");
            if (!in) bad = 1;
            else {
                while ((got = fread(buffer, 1, sizeof(buffer), in)) != 0) {
                    for (i = 0; i < got; ++i) second = (second ^ buffer[i]) * 16777619u;
                    bytes2 += got;
                }
                if (ferror(in)) bad = 1;
                fclose(in);
            }
            if (hash != second || bytes != bytes2) bad = 1;
            fprintf(report, "%s %s%s bytes=%u fnv1a=%08x\n", bad ? "UNSTABLE_OR_IO_ERROR" : "COPIED", names[n], suffix ? ".inf" : "", bytes, hash);
            if (bad) ++failed; else ++copied;
            fflush(report);
            write_status(n*2+suffix+1, copied, failed, "RUNNING");
        }
    }
    fprintf(report, "FINISHED copied=%u failed=%u\n", copied, failed);
    fflush(report); fclose(report);
    write_status(26, copied, failed, failed ? "FAILED" : "COMPLETE");
    {
        FILE *marker=fopen(failed ? "/bd0/SMEG_BACKUP/FAILED.txt" : "/bd0/SMEG_BACKUP/COMPLETE.txt", "wb");
        if(marker) {
            fprintf(marker, "Export %s. Copied=%u failed=%u.\n"
                    "Host validation of SQLite, compression and checksums is still required.\n"
                    "No feature parameters were changed by this exporter.\n",
                    failed ? "failed" : "finished", copied, failed);
            fflush(marker); fclose(marker);
        }
    }
    printf("SMEG_RO_BACKUP_FINISHED copied=%u failed=%u\n", copied, failed);
#ifdef SMEG_EMULATOR_ONLY_NETWORK_CACHE
    if(!failed) {
        int network_status=smeg_emulator_network_cache();
        if(network_status!=0)return network_status;
#ifdef SMEG_EMULATOR_ONLY_SET_WEB
        if(smeg_emulator_set_web()!=0)return -25;
#endif
        return smeg_emulator_network_finish();
    }
#else
#ifdef SMEG_EMULATOR_ONLY_SET_WEB
    if (!failed) {
#ifdef SMEG_RUNTIME_AND_WEB
        if(smeg_usb_runtime_gates()!=0)return -24;
#endif
        return smeg_emulator_set_web();
    }
#endif
#endif
#ifdef SMEG_EMULATOR_ONLY_SET_PORTAL
    if(!failed)return smeg_emulator_set_portal();
#endif
    return failed ? -3 : 0;
}

/* No unverified private GUI calls: progress is written only on the USB.
 * This counts attempted files, including optional files which may be absent.
 * COMPLETE means all mandatory sources copied with stable size and hash;
 * it does not claim a transactionally consistent snapshot across databases.
 */
static void write_status(unsigned attempted, unsigned copied, unsigned failed,
                         const char *state)
{
    FILE *f=fopen("/bd0/SMEG_BACKUP/status.txt", "wb");
    if(!f)return;
    fprintf(f, "State: %s\nFile checks: %u/26 (%u%%)\nCopied: %u\nErrors: %u\n",
            state, attempted, attempted*100/26, copied, failed);
    fflush(f); fclose(f);
}
