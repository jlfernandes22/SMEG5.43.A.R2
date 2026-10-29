/* SPDX-License-Identifier: GPL-2.0-or-later
 * Experimental MPC5121 NFC. Real register-driven NAND transactions and IRQ;
 * no FlashFX filesystem content or shell output is synthesized by this model.
 * Register source: NXP MPC5121ERM and U-Boot mpc5121_nfc.c.
 */
typedef struct SmegNFC {
    MemoryRegion iomem;
    uint8_t bytes[0x2000];
    uint8_t command, address[8], status, id[6];
    unsigned naddr;
    const uint8_t *flash; /* Legacy read-only logical-page backend. */
    uint64_t flash_size;
    BlockBackend *nand; /* Explicit writable interleaved data+OOB backend. */
    uint64_t nand_size;
    unsigned page_size, spare_size, pages_per_block;
    bool program_pending;
    bool trace_io;
    bool status_reported;
    uint64_t reads, programs, erases;
    void (*irq_change)(void *opaque, bool level);
    void *irq_opaque;
} SmegNFC;

static void smeg_nfc_update_irq(SmegNFC *n)
{
    bool done = n->bytes[0x1e1c] & 0x80;
    bool masked = n->bytes[0x1e1b] & 0x10;
    if (n->irq_change) {
        n->irq_change(n->irq_opaque, done && !masked);
    }
}

static uint64_t smeg_nfc_row(SmegNFC *n, unsigned first)
{
    uint64_t page = 0;
    for (unsigned i = first; i < n->naddr; i++) {
        page |= (uint64_t)n->address[i] << ((i - first) * 8);
    }
    return page;
}

static int smeg_nfc_load_page(SmegNFC *n, uint64_t page, uint8_t *data)
{
    uint64_t stride = n->page_size + n->spare_size;
    memset(data, 0xff, stride);
    if (n->nand) {
        if (page >= n->nand_size / stride) {
            return -1;
        }
        return blk_pread(n->nand, page * stride, stride, data, 0);
    }
    if (n->flash && page * n->page_size + n->page_size <= n->flash_size) {
        memcpy(data, n->flash + page * n->page_size, n->page_size);
    }
    return 0;
}

static void smeg_nfc_read_page(SmegNFC *n)
{
    uint8_t data[4096 + 256];
    unsigned sections = n->page_size / 512;
    unsigned spare_chunk = n->spare_size / sections;
    uint64_t page = smeg_nfc_row(n, 2);
    memset(n->bytes, 0xff, 0x1400);
    if (smeg_nfc_load_page(n, page, data) < 0) {
        n->status |= 1;
        return;
    }
    memcpy(n->bytes, data, n->page_size);
    for (unsigned i = 0; i < sections; i++) {
        memcpy(n->bytes + 0x1000 + i * 0x40,
               data + n->page_size + i * spare_chunk, spare_chunk);
    }
    /* Ideal ECC engine for this error-free virtual medium. No bit errors
     * are introduced; the hardware reports zero corrected/uncorrectable bits. */
    n->bytes[0x1e0c] = n->bytes[0x1e0d] = 0;
    n->bytes[0x1e0e] = n->bytes[0x1e0f] = 0;
    n->reads++;
    if (n->trace_io || n->reads <= 3 || n->reads % 1024 == 0) {
        qemu_log_mask(LOG_UNIMP,
                      "SMEG NFC read page=%" PRIu64 " count=%" PRIu64 "\n",
                      page, n->reads);
    }
}

static void smeg_nfc_program_page(SmegNFC *n)
{
    uint8_t old[4096 + 256], data[4096 + 256];
    uint64_t page = smeg_nfc_row(n, 2);
    unsigned stride = n->page_size + n->spare_size;
    unsigned sections = n->page_size / 512;
    unsigned spare_chunk = n->spare_size / sections;
    n->status = 0xc0;
    if (!n->nand || smeg_nfc_load_page(n, page, old) < 0) {
        n->status |= 1;
        return;
    }
    memcpy(data, n->bytes, n->page_size);
    for (unsigned i = 0; i < sections; i++) {
        memcpy(data + n->page_size + i * spare_chunk,
               n->bytes + 0x1000 + i * 0x40, spare_chunk);
    }
    /* NAND programs can only change 1 to 0; erase is a separate operation. */
    for (unsigned i = 0; i < stride; i++) {
        data[i] &= old[i];
    }
    if (blk_pwrite(n->nand, page * stride, stride, data, 0) < 0) {
        n->status |= 1;
    }
    n->programs++;
    if (n->trace_io || n->programs <= 2 || !(n->programs % 64) ||
        (n->status & 1)) {
        qemu_log_mask(LOG_UNIMP, "SMEG NFC program page=%" PRIu64
                      " status=%02x count=%" PRIu64 "\n",
                      page, n->status, n->programs);
    }
}

static void smeg_nfc_erase_block(SmegNFC *n)
{
    g_autofree uint8_t *data = NULL;
    uint64_t page = smeg_nfc_row(n, 0);
    unsigned stride = n->page_size + n->spare_size;
    unsigned block_bytes = stride * n->pages_per_block;
    int result;
    page -= page % n->pages_per_block;
    n->status = 0xc0;
    if (!n->nand || (page + n->pages_per_block) * stride > n->nand_size) {
        n->status |= 1;
        return;
    }
    /* One NAND erase changes the complete data+OOB block to erased bytes.
     * Submit it as one aligned host write instead of 64 unaligned page
     * writes; completion and the guest IRQ still follow successful I/O. */
    data = g_malloc(block_bytes);
    memset(data, 0xff, block_bytes);
    if (n->trace_io) {
        qemu_log_mask(LOG_UNIMP,
                      "SMEG NFC erase write begin page=%" PRIu64
                      " offset=%" PRIu64 " bytes=%u\n",
                      page, page * stride, block_bytes);
    }
    result = blk_pwrite(n->nand, page * stride, block_bytes, data, 0);
    if (n->trace_io) {
        qemu_log_mask(LOG_UNIMP,
                      "SMEG NFC erase write end page=%" PRIu64
                      " result=%d\n", page, result);
    }
    if (result < 0) {
        n->status |= 1;
    }
    n->erases++;
    if (n->trace_io || n->erases <= 2 || !(n->erases % 64) ||
        (n->status & 1)) {
        qemu_log_mask(LOG_UNIMP, "SMEG NFC erase block=%" PRIu64
                      " status=%02x count=%" PRIu64 "\n",
                      page / n->pages_per_block, n->status, n->erases);
    }
}

static uint64_t smeg_nfc_read(void *opaque, hwaddr off, unsigned size)
{
    SmegNFC *n = opaque;
    uint64_t result = 0;
    for (unsigned i = 0; i < size; i++) {
        result = (result << 8) | n->bytes[off + i];
    }
    return result;
}

static void smeg_nfc_write(void *opaque, hwaddr off, uint64_t value,
                            unsigned size)
{
    SmegNFC *n = opaque;
    for (unsigned i = 0; i < size; i++) {
        n->bytes[off + i] = value >> ((size - i - 1) * 8);
    }
    if (off == 0x1e1a && size == 2) {
        if (value & 0x40) {
            n->bytes[off + 1] &= ~0x40; /* Controller reset self-clears. */
            n->naddr = 0;
        }
        smeg_nfc_update_irq(n);
        return;
    }
    if (off != 0x1e1c || size != 2) {
        return;
    }
    /* Writing zero clears completion. It does not start another operation. */
    if (!(value & 0x3f)) {
        smeg_nfc_update_irq(n);
        return;
    }
    if (value & 1) {
        n->command = n->bytes[0x1e09];
        if (n->command == 0 || n->command == 0x90 || n->command == 0xff ||
            n->command == 0x60 || n->command == 0x80) {
            n->naddr = 0;
        }
        if (n->command == 0xff) {
            n->status = 0xc0;
            n->program_pending = false;
        } else if (n->command == 0xd0) {
            smeg_nfc_erase_block(n);
        } else if (n->command == 0x10 && n->program_pending) {
            smeg_nfc_program_page(n);
            n->program_pending = false;
        }
    }
    if ((value & 2) && n->naddr < sizeof(n->address)) {
        n->address[n->naddr++] = n->bytes[0x1e07];
    }
    if (value & 4) {
        n->program_pending = true; /* NAND input staged until PAGEPROG. */
    }
    if (value & 8) {
        smeg_nfc_read_page(n);
    }
    if (value & 0x10) {
        memset(n->bytes, 0xff, 16);
        memcpy(n->bytes, n->id, sizeof(n->id));
    }
    if (value & 0x20) {
        /* NAND STATUS repeats the same value on each read strobe. The
         * local x8 BSP samples byte0 or byte1 of a four-byte NFC transfer,
         * depending on its buffer-endian flag (reader at 0x5bd300). */
        memset(n->bytes, n->status, 4);
        if (!n->status_reported) {
            qemu_log_mask(LOG_UNIMP,
                          "SMEG NFC first STATUS=%02x buffer=%02x%02x%02x%02x "
                          "config1=%02x%02x\n", n->status,
                          n->bytes[0], n->bytes[1], n->bytes[2], n->bytes[3],
                          n->bytes[0x1e1a], n->bytes[0x1e1b]);
            n->status_reported = true;
        }
    }
    n->bytes[0x1e1c] = 0x80;
    n->bytes[0x1e1d] = 0; /* Operation bits self-clear on completion. */
    smeg_nfc_update_irq(n);
    if (n->trace_io) {
        qemu_log_mask(LOG_UNIMP,
                      "SMEG NFC cmd=%02x operation=%04" PRIx64
                      " addr-cycles=%u completed\n",
                      n->command, value, n->naddr);
    }
}

static const MemoryRegionOps smeg_nfc_ops = {
    .read = smeg_nfc_read,
    .write = smeg_nfc_write,
    .endianness = DEVICE_BIG_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 4 },
    .impl = { .min_access_size = 1, .max_access_size = 4 },
};
