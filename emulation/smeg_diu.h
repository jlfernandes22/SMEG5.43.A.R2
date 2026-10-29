/* SPDX-License-Identifier: GPL-2.0-or-later
 * MPC5121ERM chapter12 DIU scanout: little-endian area descriptors in RAM.
 * This displays guest pixels, not a replacement HMI or a GPU renderer.
 */
static unsigned smeg_diu_component(uint32_t pixel, uint32_t format,
                                    unsigned component, bool alpha)
{
    unsigned shift = 0;
    for (unsigned i = 0; i < component; i++) {
        shift += (format >> (i * 4)) & 15;
    }
    unsigned bits = (format >> (component * 4)) & 15;
    if (!bits || bits > 8) {
        return 0;
    }
    unsigned value = (pixel >> shift) & ((1U << bits) - 1);
    return alpha ? value * 255 / ((1U << bits) - 1) : value << (8 - bits);
}

/* The native surface is BGRA8888. Avoid decoding its fixed components
 * and alpha-blending every pixel at each display refresh when this exact
 * hardware configuration is active. Other formats and area layouts use the
 * full model. */
static bool smeg_diu_primary_fast(SmegMachineState *s, DisplaySurface *surface,
                                  unsigned width, unsigned height)
{
    uint32_t descriptor = 0;
    unsigned active_plane = 0;
    uint8_t ad[40];
    for (unsigned plane = 0; plane < 3; plane++) {
        uint32_t candidate = smeg_reg_get(s, 0x2100 + plane * 4, 4);
        if (candidate) {
            if (descriptor) {
                return false;
            }
            descriptor = candidate;
            active_plane = plane;
        }
    }
    if (!descriptor ||
        (uint64_t)descriptor + sizeof(ad) > MACHINE(s)->ram_size ||
        address_space_read(&address_space_memory, descriptor,
                           MEMTXATTRS_UNSPECIFIED, ad, sizeof(ad)) != MEMTX_OK) {
        return false;
    }
    uint32_t bitmap = ldl_le_p(ad + 4);
    size_t bytes = (size_t)width * height * 4;
    if (ldl_le_p(ad) != 0x06338888 ||
        ldl_le_p(ad + 8) != ((height << 12) | width) ||
        ldl_le_p(ad + 12) != ((height << 16) | width) ||
        ldl_le_p(ad + 16) || ldl_le_p(ad + 20) || ldl_le_p(ad + 32) ||
        (ldl_le_p(ad + 28) & 0xffffff) <=
            (ldl_le_p(ad + 24) & 0xffffff) ||
        !bitmap || (uint64_t)bitmap + bytes > MACHINE(s)->ram_size) {
        return false;
    }
    /* This board has identity-mapped contiguous RAM; never access MMIO here. */
    const uint8_t *ram = memory_region_get_ram_ptr(MACHINE(s)->ram);
    const uint8_t *pixels = ram + bitmap;
    uint32_t background = smeg_reg_get(s, 0x2120, 4) & 0xffffff;
    if (s->diu_fast_bytes != bytes) {
        s->diu_fast_cache = g_realloc(s->diu_fast_cache, bytes);
        s->diu_fast_bytes = bytes;
        s->diu_fast_valid = false;
    }
    if (s->diu_fast_valid && s->diu_fast_surface == surface &&
        s->diu_fast_plane == active_plane &&
        s->diu_fast_background == background &&
        s->diu_fast_width == width && s->diu_fast_height == height &&
        !memcmp(s->diu_fast_cache, pixels, bytes)) {
        return true;
    }
    memcpy(s->diu_fast_cache, pixels, bytes);
    for (unsigned y = 0; y < height; y++) {
        uint32_t *dest = (uint32_t *)(surface_data(surface) +
                                    y * surface_stride(surface));
        const uint8_t *row = s->diu_fast_cache + (size_t)y * width * 4;
        for (unsigned x = 0; x < width; x++) {
            uint32_t pixel = ldl_le_p(row + 4 * x);
            unsigned alpha = active_plane ? pixel >> 24 : 255;
            if (alpha == 255) {
                dest[x] = pixel & 0xffffff;
            } else {
                unsigned r = (((pixel >> 16) & 255) * alpha +
                              ((background >> 16) & 255) * (255 - alpha)) / 255;
                unsigned g = (((pixel >> 8) & 255) * alpha +
                              ((background >> 8) & 255) * (255 - alpha)) / 255;
                unsigned b = ((pixel & 255) * alpha +
                              (background & 255) * (255 - alpha)) / 255;
                dest[x] = (r << 16) | (g << 8) | b;
            }
        }
    }
    s->diu_fast_valid = true;
    s->diu_fast_surface = surface;
    s->diu_fast_background = background;
    s->diu_fast_plane = active_plane;
    s->diu_fast_width = width;
    s->diu_fast_height = height;
    dpy_gfx_update(s->diu_console, 0, 0, width, height);
    return true;
}

static void smeg_diu_update(void *opaque)
{
    SmegMachineState *s = opaque;
    DisplaySurface *surface = qemu_console_surface(s->diu_console);
    uint32_t size = smeg_reg_get(s, 0x2128, 4);
    unsigned width = size & 0x7ff, height = (size >> 16) & 0x7ff;
    if (smeg_reg_get(s, 0x211c, 4) != 1 || !width || !height) {
        return;
    }
    if (surface_width(surface) != width || surface_height(surface) != height) {
        s->diu_fast_valid = false;
        qemu_console_resize(s->diu_console, width, height);
        surface = qemu_console_surface(s->diu_console);
    }
    if (surface_bits_per_pixel(surface) != 32) {
        return;
    }
    if (smeg_diu_primary_fast(s, surface, width, height)) {
        return;
    }
    s->diu_fast_valid = false;
    uint32_t background = smeg_reg_get(s, 0x2120, 4) & 0xffffff;
    for (unsigned y = 0; y < height; y++) {
        uint32_t *line = (uint32_t *)(surface_data(surface) +
                                     y * surface_stride(surface));
        for (unsigned x = 0; x < width; x++) {
            line[x] = background;
        }
    }
    for (unsigned plane = 0; plane < 3; plane++) {
        uint32_t descriptor = smeg_reg_get(s, 0x2100 + plane * 4, 4);
        for (unsigned area = 0; descriptor && area < 16; area++) {
            uint8_t ad[40];
            if ((uint64_t)descriptor + sizeof(ad) > MACHINE(s)->ram_size ||
                address_space_read(&address_space_memory, descriptor,
                                   MEMTXATTRS_UNSPECIFIED, ad, sizeof(ad)) != MEMTX_OK) {
                break;
            }
            uint32_t format = ldl_le_p(ad), bitmap = ldl_le_p(ad + 4);
            uint32_t source = ldl_le_p(ad + 8), aoi = ldl_le_p(ad + 12);
            uint32_t origin = ldl_le_p(ad + 16), display = ldl_le_p(ad + 20);
            unsigned bpp = ((format >> 16) & 3) + 1;
            unsigned sw = source & 0xfff, sh = (source >> 12) & 0xfff;
            unsigned aw = aoi & 0x7ff, ah = (aoi >> 16) & 0x7ff;
            unsigned sx = origin & 0xfff, sy = (origin >> 16) & 0xfff;
            unsigned dx = display & 0xfff, dy = (display >> 16) & 0xfff;
            uint32_t cmax = ldl_le_p(ad + 24), cmin = ldl_le_p(ad + 28);
            descriptor = ldl_le_p(ad + 32);
            if (!bitmap || !sw || !sh || !aw || !ah || (format & 0x40000) ||
                sx + aw > sw || sy + ah > sh ||
                (uint64_t)bitmap + (uint64_t)sw * sh * bpp > MACHINE(s)->ram_size) {
                continue;
            }
            g_autofree uint8_t *row = g_malloc(sw * bpp);
            for (unsigned y = 0; y < ah && dy + y < height; y++) {
                unsigned source_y = (aoi & 0x80000000) ? sy + ah - y - 1 : sy + y;
                if (address_space_read(&address_space_memory,
                                       bitmap + source_y * sw * bpp,
                                       MEMTXATTRS_UNSPECIFIED, row, sw * bpp) != MEMTX_OK) {
                    break;
                }
                uint32_t *dest = (uint32_t *)(surface_data(surface) +
                                            (dy + y) * surface_stride(surface));
                for (unsigned x = 0; x < aw && dx + x < width; x++) {
                    unsigned source_x = (aoi & 0x40000000) ? sx + aw - x - 1 : sx + x;
                    uint8_t *p = row + source_x * bpp;
                    uint32_t pixel = 0;
                    for (unsigned byte = 0; byte < bpp; byte++) {
                        /* BYTE_F=0 reverses the source pixel's byte order. */
                        unsigned index = (format & 0x10000000) ? byte : bpp - byte - 1;
                        pixel = (pixel << 8) | p[index];
                    }
                    unsigned r = smeg_diu_component(pixel, format, (format >> 19) & 3, false);
                    unsigned g = smeg_diu_component(pixel, format, (format >> 21) & 3, false);
                    unsigned b = smeg_diu_component(pixel, format, (format >> 23) & 3, false);
                    unsigned ac = (format >> 25) & 7;
                    unsigned alpha = plane == 0 ? 255 :
                                     ac == 4 ? source >> 24 :
                                     ac < 4 ? smeg_diu_component(pixel, format, ac, true) : 0;
                    if ((cmin & 0xffffff) <= (cmax & 0xffffff) &&
                        r >= ((cmin >> 16) & 255) && r <= ((cmax >> 16) & 255) &&
                        g >= ((cmin >> 8) & 255) && g <= ((cmax >> 8) & 255) &&
                        b >= (cmin & 255) && b <= (cmax & 255)) {
                        alpha = 0;
                    }
                    uint32_t old = dest[dx + x];
                    r = (r * alpha + ((old >> 16) & 255) * (255 - alpha)) / 255;
                    g = (g * alpha + ((old >> 8) & 255) * (255 - alpha)) / 255;
                    b = (b * alpha + (old & 255) * (255 - alpha)) / 255;
                    dest[dx + x] = (r << 16) | (g << 8) | b;
                }
            }
        }
    }
    dpy_gfx_update(s->diu_console, 0, 0, width, height);
}

static void smeg_diu_vblank(void *opaque)
{
    SmegMachineState *s = opaque;
    if (smeg_reg_get(s, 0x211c, 4) == 1) {
        s->diu_status |= 1; /* Real modeled scanout frame boundary, not GPU completion. */
        smeg_update_irq(s);
    }
    /* Explicit 60-Hz bench panel; register-based pixel clock derivation pending. */
    timer_mod(s->diu_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 16666667);
}

static const GraphicHwOps smeg_diu_graphics_ops = {
    .gfx_update = smeg_diu_update,
};

/* The original MMU_MapPage stores a little-endian physical address per
 * 4KiB GPU page. Eight table base registers each cover 1024 PTEs (32MiB).
 * This helper validates RAM destinations; it never treats a GPU VA as a
 * physical CPU address and never invokes guest code to manufacture success. */
static bool smeg_mbx_translate(SmegMachineState *s, uint32_t va, hwaddr *pa)
{
    uint8_t bytes[4];
    uint32_t table, page;
    if (va >= 32 * MiB || !(s->mbx_regs[0x1020 / 4] & 1)) {
        return false;
    }
    table = s->mbx_regs[(0x1000 / 4) + (va >> 22)];
    if ((table & 0xfff) || (uint64_t)table + 4096 > MACHINE(s)->ram_size ||
        address_space_read(&address_space_memory,
                           table + ((va >> 12) & 0x3ff) * 4,
                           MEMTXATTRS_UNSPECIFIED, bytes, 4) != MEMTX_OK) {
        return false;
    }
    page = ldl_le_p(bytes);
    if (!page || (page & 0xfff) ||
        (uint64_t)page + 4096 > MACHINE(s)->ram_size) {
        return false;
    }
    *pa = page + (va & 0xfff);
    return true;
}

static void smeg_mbx_pb_initialize(SmegMachineState *s)
{
    uint32_t first = s->mbx_regs[0x828 / 4];
    uint32_t last = s->mbx_regs[0x82c / 4];
    uint32_t list = s->mbx_regs[0x824 / 4];
    uint32_t background = s->mbx_regs[0x83c / 4];
    hwaddr first_pa = 0, last_pa = 0, list_pa = 0, background_pa;
    bool valid = first > 0 && first <= last && last < 8192 &&
                 !(list & 0xfff) && !(background & 0xfff) &&
                 s->mbx_regs[0x838 / 4] == 1;

    s->mbx_pb_initialized = false;
    s->mbx_pb_free_count = 0;
    memset(s->mbx_pb_free, 0, sizeof(s->mbx_pb_free));
    /* The native driver allocates a 16KiB freelist buffer and reserves the
     * first PB page for its initialized background object. Validate every
     * backing page before accepting this internal resource initialization. */
    valid = valid && smeg_mbx_translate(s, background, &background_pa) &&
            smeg_mbx_translate(s, list, &list_pa);
    for (unsigned i = 0; valid && i < 4; i++) {
        hwaddr pa;
        valid = smeg_mbx_translate(s, list + i * 4096, &pa);
    }
    for (uint32_t page = first; valid && page <= last; page++) {
        hwaddr pa;
        valid = smeg_mbx_translate(s, page << 12, &pa);
        if (valid) {
            if (page == first) {
                first_pa = pa;
            }
            last_pa = pa;
            s->mbx_pb_free[page] = true;
            s->mbx_pb_free_count++;
        }
    }
    if (!valid) {
        memset(s->mbx_pb_free, 0, sizeof(s->mbx_pb_free));
        s->mbx_pb_free_count = 0;
        qemu_log_mask(LOG_GUEST_ERROR,
                      "SMEG MBX PB invalid allocation first=%x last=%x "
                      "freelistVA=%08x backgroundVA=%08x; not completed\n",
                      first, last, list, background);
        return;
    }
    s->mbx_pb_first = first;
    s->mbx_pb_last = last;
    s->mbx_pb_initialized = true;
    /* Partial SPM model: maintain a real device-owned free-page set. The
     * proprietary freelist RAM entry encoding remains UNIMPLEMENTED: do not
     * invent opaque words in guest memory. No allocation/TA/render command
     * is executed or acknowledged by this initialization event. */
    s->mbx_regs[0x12c / 4] |= 0x40;
    qemu_log_mask(LOG_UNIMP,
                  "SMEG MBX PB initialized device-owned pages=%u range=%x..%x "
                  "firstPA=%08" HWADDR_PRIx " lastPA=%08" HWADDR_PRIx
                  " freelistVA=%08x freelistPA=%08" HWADDR_PRIx
                  "; proprietary freelist RAM encoding unimplemented; "
                  "rendering unsupported\n",
                  s->mbx_pb_free_count, first, last, first_pa, last_pa,
                  list, list_pa);
}

static uint64_t smeg_mbx_read(void *opaque, hwaddr off, unsigned size)
{
    SmegMachineState *s = opaque;
    uint32_t value = 0;
    if (off < sizeof(s->mbx_regs)) {
        value = s->mbx_regs[off / 4];
    } else if (!s->mbx_unimplemented[off >> 12]) {
        s->mbx_unimplemented[off >> 12] = true;
        qemu_log_mask(LOG_UNIMP,
                      "SMEG MBX unsupported read pc=%08" PRIx64
                      " off=%08" HWADDR_PRIx " size=%u\n",
                      (uint64_t)s->cpu->env.nip, off, size);
    }
    /* MBX is internally little-endian. SPCR[MBXBSEN] swaps the CPU bus view. */
    if (!(smeg_reg_get(s, 0x104, 4) & 0x400)) {
        value = bswap32(value);
    }
    if (off == 0xf00 || off == 0xf10) {
        qemu_log_mask(LOG_UNIMP, "SMEG MBX identity read off=%04" HWADDR_PRIx
                      " value=%08x\n", off, value);
    }
    return value;
}

static void smeg_mbx_write(void *opaque, hwaddr off, uint64_t value, unsigned size)
{
    SmegMachineState *s = opaque;
    if (!(smeg_reg_get(s, 0x104, 4) & 0x400)) {
        value = bswap32(value);
    }
    if (s->trace_io || off == 0x6d8) {
        qemu_log_mask(LOG_UNIMP,
                      "SMEG MBX W pc=%08" PRIx64 " off=%04" HWADDR_PRIx
                      " value=%08" PRIx64 "\n",
                      (uint64_t)s->cpu->env.nip, off, value);
        if (off == 0x6d8) {
            qemu_log_mask(LOG_UNIMP,
                          "SMEG MBX PB config 824=%08x 828=%08x 82c=%08x "
                          "838=%08x 83c=%08x\n",
                          s->mbx_regs[0x824 / 4], s->mbx_regs[0x828 / 4],
                          s->mbx_regs[0x82c / 4], s->mbx_regs[0x838 / 4],
                          s->mbx_regs[0x83c / 4]);
        }
    }
    if (off >= sizeof(s->mbx_regs)) {
        if (!s->mbx_unimplemented[off >> 12]) {
            s->mbx_unimplemented[off >> 12] = true;
            qemu_log_mask(LOG_UNIMP,
                          "SMEG MBX unsupported write pc=%08" PRIx64
                          " off=%08" HWADDR_PRIx
                          " size=%u value=%08" PRIx64 "\n",
                          (uint64_t)s->cpu->env.nip, off, size, value);
        }
        return;
    }
    if (off == 0xf00 || off == 0xf10) {
        return; /* Read-only identity/feature registers. */
    }
    if (off == 0x1020) {
        /* Original MMU_Enable/Disable at 0x0202a54c/0x0202a500:
         * bit0 requests enabled state; bit16 acknowledges that state.
         * This configures the GPU MMU, not command/render completion.
         * Page-table bases are the eight real registers 0x1000..0x101c. */
        s->mbx_regs[off / 4] = (value & ~0x10000U) |
                              ((value & 1) ? 0x10000 : 0);
        if (s->trace_io) {
            qemu_log_mask(LOG_UNIMP,
                      "SMEG MBX MMU enable=%u control=%08x pc=%08" PRIx64 "\n",
                      !!(value & 1), s->mbx_regs[off / 4],
                      (uint64_t)s->cpu->env.nip);
        }
    } else if (off == 0x134) {
        s->mbx_regs[0x12c / 4] &= ~value; /* Native PB event is polled here. */
    } else {
        s->mbx_regs[off / 4] = value;
    }
    if (off == 0x6d8) {
        if (value == 0x09000000) {
            smeg_mbx_pb_initialize(s);
        } else {
            qemu_log_mask(LOG_UNIMP,
                          "SMEG MBX unsupported command %08" PRIx64
                          "; not completed\n", value);
        }
    }
    /* Command submission is deliberately not acknowledged as rendered. */
}

static const MemoryRegionOps smeg_mbx_ops = {
    .read = smeg_mbx_read,
    .write = smeg_mbx_write,
    .endianness = DEVICE_BIG_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};
