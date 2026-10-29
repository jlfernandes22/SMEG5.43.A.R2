/* QEMU-only resource installation experiment. No configuration setters,
 * replacement databases, application/BSP writes, or automatic reboot.
 * Native WriteBigHarmony owns all NAND controller operations.
 */
#ifndef SMEG_BACKUP_INCLUDED_EXTERNALLY
#define SMEG_EMULATOR_ONLY_SET_WEB 1
#define smeg_emulator_set_web smeg_install_theme_resources
#include "usb_backup_readonly.c"
#undef smeg_emulator_set_web
#undef SMEG_EMULATOR_ONLY_SET_WEB
#endif
#include "theme_resource_contract.h"
#ifndef RESOURCE_PROGRESS_STAGE
static int resource_progress_noop(const char *m,unsigned a,unsigned b,unsigned c)
{(void)m;(void)a;(void)b;(void)c;return 0;}
#define RESOURCE_PROGRESS_STAGE(m,p) resource_progress_noop(m,p,0,0)
#define RESOURCE_PROGRESS_BEGIN(m,l,h,t) resource_progress_noop(m,l,h,t)
#define RESOURCE_PROGRESS_ADD(n) resource_progress_noop("bytes",n,0,0)
#define RESOURCE_PROGRESS_FLUSH() resource_progress_noop("flush",0,0,0)
#define RESOURCE_PROGRESS_FAILED() resource_progress_noop("failed",0,0,0)
#define RESOURCE_PROGRESS_DESTRUCTIVE() ((void)0)
#endif

static unsigned hash_bytes(const void *data, unsigned bytes)
{
    const unsigned char *p = data;
    unsigned h = 2166136261u;
    while (bytes--) h = (h ^ *p++) * 16777619u;
    return h;
}

#include "theme_source_verify.h"
#define RESOURCE_LOG(...) do {if(log)fprintf(log,__VA_ARGS__);else printf(__VA_ARGS__);} while(0)

static int resource_close_log(FILE **log)
{
    int bad;
    if (!*log) return 0;
    bad = ferror(*log) != 0;
    if (fflush(*log) != 0) bad = 1;
    if (fclose(*log) != 0) bad = 1;
    *log = 0;
    return bad ? -1 : 0;
}

int smeg_install_theme_resources(void)
{
    int (*read_pre)(int, void *) = (int (*)(int, void *))resource_api[0].address;
    int (*read_big)(int, void *) = (int (*)(int, void *))resource_api[1].address;
    int (*read_entry)(int, int, void *) = (int (*)(int, int, void *))resource_api[2].address;
    int (*write_bank)(int, const char *) = (int (*)(int, const char *))resource_api[3].address;
#ifdef RESOURCE_COMPLETE_READBACK
    int (*read_payload)(int, const void *, void *) = (int (*)(int, const void *, void *))resource_api[RESOURCE_READ_API].address;
    unsigned char *payload = 0;
    extern void *malloc(size_t);
    extern void free(void *);
#endif
#ifdef RESOURCE_ERASE_HEADER
    int (*erase_header)(int) = (int (*)(int))resource_api[4].address;
#endif
#ifdef RESOURCE_ERASE_ALL
    int (*erase_all)(void) = (int (*)(void))resource_api[4].address;
#endif
    /* ReadBigHarmonyBigHeader copies preheader.HEADER_SIZE bytes, including
     * the directory entries, rather than only its fixed 36-byte prefix. */
    /* The native USB loader task has a 4 KiB stack. Keep the 2.4 KiB readback
     * workspace out of it, leaving room for DOSFS/USB and NAND driver calls.
     * This one-shot module is guarded by its unique backup destination. */
    static unsigned char pre[168], big[2048], entry[216];
    unsigned i, bank, pass, total_bytes=0, order[RESOURCE_COUNT];
    int status = -1, log_bad = 0, first_error=0, write_result[RESOURCE_COUNT];
    FILE *log = fopen("/bd0/SMEG_BACKUP/theme-install.txt", "wb");
    if (!log) return -60;
    for(i=0;i<RESOURCE_COUNT;++i){order[i]=i;write_result[i]=-1;}
    RESOURCE_LOG("QEMU ONLY: native USB theme-resource experiment; no preference setters\n");
    for (i = 0; i < sizeof(resource_api)/sizeof(resource_api[0]); ++i) {
        if (hash_bytes((const void *)resource_api[i].address, resource_api[i].bytes)
                != resource_api[i].hash) {
            RESOURCE_LOG("ABORT BSP fingerprint mismatch index=%u\n", i);
            status = -61; goto done;
        }
    }
    if (fflush(log)) { status = -67; goto done; }
    /* Verify all original bank headers before the first destructive write. */
    for (bank = 1; bank <= 2; ++bank) {
        if (read_pre((int)bank, pre) || hash_bytes(pre, sizeof(pre)) != original_pre_hash[bank-1]) {
            RESOURCE_LOG("ABORT original bank%u preheader mismatch\n", bank);
            status = -62; goto done;
        }
    }
    {
        int log_error = fflush(log) != 0;
        if (fclose(log) != 0) log_error = 1;
        log = 0;
        if (log_error) { status = -67; goto done; }
    }
    /* WriteBigHarmony also reads each .inf after erasure. Validate these
     * generated sidecars before any destructive call, using the same two
     * consecutive complete source checks as the bank data. */
    if (RESOURCE_INF_COUNT != RESOURCE_COUNT) { status = -68; goto done; }
    for(i=0;i<RESOURCE_COUNT;++i){
        if(resource_files[i].bytes>(~0u-total_bytes)/2u){status=-68;goto done;}
        total_bytes+=resource_files[i].bytes*2u;
    }
    for(i=0;i<RESOURCE_INF_COUNT;++i){
        if(!resource_inf_files[i].bytes || resource_inf_files[i].bytes>(~0u-total_bytes)/2u){status=-68;goto done;}
        total_bytes+=resource_inf_files[i].bytes*2u;
    }
    if(RESOURCE_PROGRESS_BEGIN("USB CRC",5,35,total_bytes)){status=-160;goto done;}
    for (i = 0; i < RESOURCE_COUNT; ++i) {
        const struct ResourceFile *r = &resource_files[i];
        printf("SMEG_THEME_PREFLIGHT source=%s bytes=%u\n", r->path, r->bytes);
        if (check_source(r->path, r->bytes, r->crc32) != 0) {
            printf("SMEG_THEME_ABORT source integrity %s; see source-checks.txt\n", r->path);
            status = -63; goto done;
        }
    }
    for (i = 0; i < RESOURCE_INF_COUNT; ++i) {
        const struct ResourceInfFile *r = &resource_inf_files[i];
        printf("SMEG_THEME_PREFLIGHT sidecar=%s bytes=%u\n", r->path, r->bytes);
        if (check_source(r->path, r->bytes, r->crc32) != 0) {
            printf("SMEG_THEME_ABORT sidecar integrity %s; see source-checks.txt\n", r->path);
            status = -63; goto done;
        }
    }
#ifdef RESOURCE_COMPLETE_READBACK
    /* Allocate before erasing; a low-memory unit must fail without writes. */
    payload = malloc(RESOURCE_MAX_PAYLOAD_BYTES);
    if (!payload) { status = -90; goto done; }
    for (bank = 1; bank <= 2; ++bank) {
        char path[128]; FILE *backup;
        unsigned size;
        if(RESOURCE_PROGRESS_STAGE(bank==1?"Read original1; wait":"Read original2; wait",bank==1?35:42)){
            status=-160;goto done;
        }
        if (read_entry((int)bank, 1, entry)) { status = -91; goto done; }
        size = ((const unsigned *)entry)[208/4];
        if (!size || size > RESOURCE_MAX_PAYLOAD_BYTES || read_payload((int)bank, entry, payload)) {
            status = -92; goto done;
        }
        if(size>~0u/3u || RESOURCE_PROGRESS_BEGIN(bank==1?"Backup original1":"Backup original2",bank==1?35:42,bank==1?42:50,size*3u)){
            status=-160;goto done;
        }
        snprintf(path, sizeof(path), "/bd0/SMEG_BACKUP/original-bank%u-entry1.bin", bank);
        backup = fopen(path, "wb");
        if (!backup) { status = -93; goto done; }
        {
            unsigned written = 0;
            status = 0;
            while (written < size) {
                unsigned chunk = size - written;
                if (chunk > 1024) chunk = 1024;
                if (fwrite(payload + written, 1, chunk, backup) != chunk) { status = -94; break; }
                written += chunk;
                if(RESOURCE_PROGRESS_ADD(chunk)){status=-160;break;}
            }
            if (fflush(backup)) status = -94;
        }
        if (fclose(backup)) status = -94;
        if (status || check_source(path, size, ((const unsigned *)entry)[212/4])) {
            status = -95; goto done;
        }
        snprintf(path, sizeof(path), "/bd0/SMEG_BACKUP/original-bank%u-entry1.header", bank);
        backup = fopen(path, "wb");
        if (!backup) { status = -96; goto done; }
        status = fwrite(entry, 1, sizeof(entry), backup) == sizeof(entry) && fflush(backup) == 0 ? 0 : -97;
        if (fclose(backup)) status = -97;
        if (status) goto done;
        if(RESOURCE_PROGRESS_FLUSH()){status=-160;goto done;}
        log = fopen("/bd0/SMEG_BACKUP/theme-install.txt", "ab");
        if (!log) { status = -67; goto done; }
        RESOURCE_LOG("ORIGINAL_RESOURCE_BACKUP bank=%u bytes=%u CRC32=%08x verified=1\n",
                bank, size, ((const unsigned *)entry)[212/4]);
        {
            int log_error = fflush(log) != 0;
            if (fclose(log) != 0) log_error = 1;
            log = 0;
            if (log_error) { status = -67; goto done; }
        }
    }
#endif
    log = fopen("/bd0/SMEG_BACKUP/theme-install.txt", "ab");
    if (!log) { status = -67; goto done; }
    RESOURCE_LOG("VERIFIED all native fingerprints, original banks and source files\n");
    /* Flush/close failures must abort before the destructive operation.
     * No USB log remains open during native bank-file reads. */
    if (resource_close_log(&log)) { status = -67; goto done; }
#ifdef RESOURCE_ERASE_ALL
    /* EraseAllHarmonies derives both bank ranges from this guarded BSP.
     * Both replacement banks must already be validated before this call. */
    if (RESOURCE_COUNT != 2 || resource_files[0].bank != 1 || resource_files[1].bank != 2) {
        status = -68; goto done;
    }
    if (RESOURCE_PROGRESS_STAGE("Erase themes; wait",50)) { status = -160; goto done; }
    RESOURCE_PROGRESS_DESTRUCTIVE();
    status = erase_all();
    if(status)first_error=status;
    /* Once erased, a receipt failure alone must not prevent the native writer
     * from rebuilding the banks. Retain the error and report failure after
     * the resource writes/readbacks; do not publish catalogue flags. */
    log = fopen("/bd0/SMEG_BACKUP/theme-install.txt", "ab");
    if (!log) log_bad = 1;
    RESOURCE_LOG("ERASE_ALL_RESOURCE_BANKS_RESULT status=%d\n", status);
    RESOURCE_LOG("POST_ERASE best-effort rebuilding both banks; not guaranteed recovery\n");
    if (resource_close_log(&log)) log_bad = 1;
    /* Even an erase error can mean partially erased banks. Attempt both
     * already-validated native writes; keep the erase error for reporting. */
    order[0]=1;order[1]=0; /* Restore the selected original WARMLIGHT bank first. */
#endif
    /* No early return or verification between these native writer calls.
     * A presentation/log/native error must never suppress the other bank. */
    for (pass = 0; pass < RESOURCE_COUNT; ++pass) {
        i=order[pass];
        const struct ResourceFile *r = &resource_files[i];
        RESOURCE_PROGRESS_STAGE(r->bank==2?"Write bank2; wait":"Write bank1; wait",pass?66:52);
        log = fopen("/bd0/SMEG_BACKUP/theme-install.txt", "ab");
        if (!log) log_bad = 1;
#ifdef RESOURCE_ERASE_HEADER
        RESOURCE_LOG("ERASE_HEADER bank=%u via native EraseNandHarmony\n", r->bank);
        if (resource_close_log(&log)) log_bad=1;
        RESOURCE_PROGRESS_DESTRUCTIVE();
        status = erase_header((int)r->bank);
        if(status&&!first_error)first_error=status;
        log = fopen("/bd0/SMEG_BACKUP/theme-install.txt", "ab");
        if (!log) log_bad = 1;
        RESOURCE_LOG("ERASE_HEADER_RESULT bank=%u status=%d\n", r->bank, status);
        if (log && fflush(log)) log_bad = 1;
#endif
        RESOURCE_LOG("WRITE bank=%u path=%s bytes=%u\n", r->bank, r->path, r->bytes);
        if (resource_close_log(&log)) log_bad = 1;
        RESOURCE_PROGRESS_DESTRUCTIVE();
        status = write_bank((int)r->bank, r->path);
        write_result[i]=status;if(status&&!first_error)first_error=status;
        log = fopen("/bd0/SMEG_BACKUP/theme-install.txt", "ab");
        if (!log) log_bad = 1;
        RESOURCE_LOG("WRITE_RESULT bank=%u status=%d\n", r->bank, status);
        if (log && fflush(log)) log_bad = 1;
        if (resource_close_log(&log)) log_bad=1;
        RESOURCE_PROGRESS_STAGE(r->bank==2?"Bank2 write returned":"Bank1 write returned",pass?80:66);
    }
    log=fopen("/bd0/SMEG_BACKUP/theme-install.txt","ab");if(!log)log_bad=1;
    RESOURCE_LOG("BOTH_RESOURCE_WRITES_ATTEMPTED count=%u\n",RESOURCE_COUNT);
    for(i=0;i<RESOURCE_COUNT;++i)RESOURCE_LOG("NATIVE_WRITE_STATUS bank=%u status=%d\n",resource_files[i].bank,write_result[i]);
    if(resource_close_log(&log))log_bad=1;
    /* Verify each bank independently after BOTH writer attempts. A failed
     * bank's readback cannot prevent inspection of the other restored bank. */
    for(pass=0;pass<RESOURCE_COUNT;++pass){
        const struct ResourceFile *r;unsigned n,readback_bytes=0;
        i=order[pass];r=&resource_files[i];status=0;
        RESOURCE_PROGRESS_STAGE(r->bank==2?"Read back bank2":"Read back bank1",pass?86:80);
        log=fopen("/bd0/SMEG_BACKUP/theme-install.txt","ab");if(!log)log_bad=1;
        status = read_pre((int)r->bank, pre);
        if (status || hash_bytes(pre, sizeof(pre)) != r->pre_hash) { status = -64; goto bank_readback_done; }
        status = read_big((int)r->bank, big);
        if (status || hash_bytes(big, 36) != r->big_hash) { status = -65; goto bank_readback_done; }
#ifdef RESOURCE_COMPLETE_READBACK
        /* These sizes are used only for UI accounting. The original guarded
         * per-entry hashes and payload bounds still authorize every read. */
        for(n=0;n<r->count;++n){unsigned size=((const unsigned *)(big+36+n*216))[208/4];
            if(size>RESOURCE_MAX_PAYLOAD_BYTES || size>~0u-readback_bytes){readback_bytes=0;break;}
            readback_bytes+=size;
        }
        RESOURCE_PROGRESS_BEGIN(r->bank==2?"Flash2 CRC":"Flash1 CRC",pass?86:80,pass?92:86,readback_bytes);
#else
        (void)readback_bytes;
#endif
        for (n = 1; n <= r->count; ++n) {
            status = read_entry((int)r->bank, (int)n, entry);
            if (status || hash_bytes(entry, sizeof(entry)) != r->entry_hash[n-1]) { status = -66; goto bank_readback_done; }
#ifdef RESOURCE_COMPLETE_READBACK
            {
                unsigned j, size = ((const unsigned *)entry)[208/4], crc = ~0u;
                if (size > RESOURCE_MAX_PAYLOAD_BYTES || read_payload((int)r->bank, entry, payload)) {
                    status = -98; goto bank_readback_done;
                }
                for (j = 0; j < size; ++j){
                    crc = (crc >> 8) ^ resource_crc_table[(crc ^ payload[j]) & 255u];
                    if((j&8191u)==8191u)RESOURCE_PROGRESS_ADD(8192);
                }
                if(size&8191u)RESOURCE_PROGRESS_ADD(size&8191u);
                if ((~crc) != ((const unsigned *)entry)[212/4]) { status = -99; goto bank_readback_done; }
                RESOURCE_LOG("PAYLOAD_READBACK bank=%u entry=%u bytes=%u CRC32=%08x verified=1\n",
                        r->bank, n, size, ~crc);
            }
#endif
            RESOURCE_LOG("READBACK bank=%u entry=%u name=%.196s\n", r->bank, n, entry);
        }
bank_readback_done:
        if(status&&!first_error)first_error=status;
        RESOURCE_LOG("READBACK_BANK_RESULT bank=%u status=%d\n",r->bank,status);
        if (resource_close_log(&log)) log_bad = 1;
        RESOURCE_PROGRESS_FLUSH();
    }
    status=first_error?first_error:(log_bad?-67:(RESOURCE_PROGRESS_FAILED()?-160:0));
    log = fopen("/bd0/SMEG_BACKUP/theme-install.txt", "ab");
    if (!log && !status) status = -67;
    RESOURCE_LOG("FINISHED native USB resource installation; no configuration setters requested\n");
done:
    if(RESOURCE_PROGRESS_FLUSH()&&!status)status=-160;
#ifdef RESOURCE_COMPLETE_READBACK
    if (payload) free(payload);
#endif
    if (!log) log = fopen("/bd0/SMEG_BACKUP/theme-install.txt", "ab");
    if (log) {
        RESOURCE_LOG("INSTALL_RESULT status=%d\n", status);
        if (fflush(log) != 0 && !status) status = -67;
        if (fclose(log) != 0 && !status) status = -67;
    } else if(!status)status = -67;
    printf("SMEG_THEME_RESOURCE_INSTALL_RESULT status=%d\n", status);
    return status;
}
