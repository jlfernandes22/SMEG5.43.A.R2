/* Included after stdio declarations and the generated CRC table.
 * Keep verification storage off the native loader's small stack. No USB log
 * remains open while a source is read. Failed reads never authorize erasure.
 */
#ifndef RESOURCE_CHECK_LOG
#define RESOURCE_CHECK_LOG "/bd0/SMEG_BACKUP/source-checks.txt"
#endif
#ifndef RESOURCE_SOURCE_OPEN
#define RESOURCE_SOURCE_OPEN fopen
#define RESOURCE_SOURCE_READ fread
#define RESOURCE_SOURCE_ERROR ferror
#define RESOURCE_SOURCE_CLOSE fclose
#define RESOURCE_SOURCE_ERRNO errnoGet
#define RESOURCE_SOURCE_DELAY taskDelay
#endif
#ifndef RESOURCE_LOG_OPEN
#define RESOURCE_LOG_OPEN fopen
#define RESOURCE_LOG_ERROR ferror
#define RESOURCE_LOG_FLUSH fflush
#define RESOURCE_LOG_CLOSE fclose
#endif
extern int errnoGet(void);
static unsigned char resource_source_buffer[8192] __attribute__((aligned(64)));

static int check_source(const char *path, unsigned bytes, unsigned expected_crc)
{
    unsigned attempt, consecutive = 0;
    for (attempt = 1; attempt <= 3; ++attempt) {
        FILE *f, *log;
#ifdef RESOURCE_CHECK_PROGRESS
        if (RESOURCE_CHECK_PROGRESS(path, attempt) != 0) return -1;
#endif
        f = RESOURCE_SOURCE_OPEN(path, "rb");
        unsigned crc = ~0u, count = 0;
        size_t n, i;
        int opened = f != 0, io_error = 0, close_error = 0, progress_error = 0, matched;
        int saved_errno = opened ? 0 : RESOURCE_SOURCE_ERRNO();
        if (f) {
            while ((n = RESOURCE_SOURCE_READ(resource_source_buffer, 1,
                                      sizeof(resource_source_buffer), f)) != 0) {
                for (i = 0; i < n; ++i)
                    crc = (crc >> 8) ^ resource_crc_table[(crc ^ resource_source_buffer[i]) & 255u];
                count += n;
#ifdef RESOURCE_CHECK_BYTES
                /* UI-only callback: it must not open a USB receipt while the
                 * input stream is open. Always close input before returning. */
                if (RESOURCE_CHECK_BYTES(path, attempt, count, bytes) != 0) {
                    progress_error = 1; break;
                }
#endif
                if (count > bytes) break;
            }
            io_error = RESOURCE_SOURCE_ERROR(f);
            if (io_error) saved_errno = RESOURCE_SOURCE_ERRNO();
            close_error = RESOURCE_SOURCE_CLOSE(f);
            if (close_error) saved_errno = RESOURCE_SOURCE_ERRNO();
        }
        matched = opened && !io_error && !close_error && !progress_error
                  && count == bytes && (~crc) == expected_crc;
        if (matched)
            ++consecutive;
        else consecutive = 0;
        log = RESOURCE_LOG_OPEN(RESOURCE_CHECK_LOG, "ab");
        if (!log) return -1;
        fprintf(log, "SOURCE_CHECK path=%s attempt=%u opened=%d bytes=%u expected_bytes=%u CRC32=%08x expected_crc=%08x ferror=%d fclose=%d errno=%08x consecutive=%u buffer=%p MOD64=%u progress_error=%d\n",
                path, attempt, opened, count, bytes, ~crc, expected_crc,
                io_error, close_error, saved_errno, consecutive,
                (void *)resource_source_buffer,(unsigned)((unsigned long)resource_source_buffer & 63u),progress_error);
        {
            int log_error = RESOURCE_LOG_ERROR(log) != 0;
            if (RESOURCE_LOG_FLUSH(log) != 0) log_error = 1;
            if (RESOURCE_LOG_CLOSE(log) != 0) log_error = 1;
            if (log_error) return -1;
        }
        if (progress_error) return -1;
#ifdef RESOURCE_CHECK_RESULT
        /* Input and its attempt receipt are both closed. Buffered progress
         * receipts may be flushed here, never in RESOURCE_CHECK_BYTES. */
        if (RESOURCE_CHECK_RESULT(path, attempt, count, bytes, matched, consecutive) != 0) return -1;
#endif
        if (consecutive == 2) return 0;
        if (attempt < 3) RESOURCE_SOURCE_DELAY(1);
    }
    return -1;
}
