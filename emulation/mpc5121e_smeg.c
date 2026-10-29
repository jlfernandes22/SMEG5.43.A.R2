/*
 * Experimental SMEG+ MPC5121E bring-up harness for QEMU 9.2.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This bypasses U-Boot and models NFC, eDMA, PSC, IPIC and DIU scanout.
 * MBX command execution remains partial. An explicit software GL API backend
 * can render original application calls without changing the firmware image.
 */
#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu/log.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "exec/address-spaces.h"
#include "hw/boards.h"
#include "hw/loader.h"
#include "hw/ppc/ppc.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "hw/usb/hcd-ehci.h"
#include "qemu/bswap.h"
#include "qemu/timer.h"
#include "qemu/main-loop.h"
#include "ui/console.h"
#include "cpu.h"
#include "spr_common.h"
#include "sysemu/reset.h"
#include "sysemu/runstate.h"
#include "sysemu/rtc.h"
#include "sysemu/sysemu.h"
#include "sysemu/block-backend.h"
#include "chardev/char-fe.h"
#include "smeg_nfc.h"
#include "smeg_mcu_peer.h"
#include "smeg_bench_ecu.h"
#include "smeg_bench_environment.h"
#include "smeg_bench_alert.h"
#include "smeg_bench_led.h"
#include "smeg_dma_copy.h"
#include "smeg_sdhc.h"
#include "smeg_hci_uart.h"
#include "hw/ppc/smeg_soft_gles.h"

#define TYPE_SMEG_MACHINE MACHINE_TYPE_NAME("smeg-mpc5121e")
#define KERNEL_BASE 0x00200000ULL
#define KERNEL_ENTRY 0x00200038ULL
#define IMMR_BASE 0x80000000ULL
#define IMMR_SIZE 0x00100000ULL
#define FLASH_BASE 0xf0000000ULL
#define FLASH_SIZE (256 * MiB)
#define SMEG_SPR_IMMR 638
#define SMEG_BENCH_NET_COUNT 11

typedef struct SmegMachineState {
    MachineState parent_obj;
    PowerPCCPU *cpu;
    MemoryRegion immr;
    MemoryRegion flash;
    MemoryRegion mbx;
    QemuConsole *diu_console;
    QEMUTimer *diu_timer;
    QEMUBH *diu_present_bh;
    uint8_t *diu_fast_cache;
    size_t diu_fast_bytes;
    DisplaySurface *diu_fast_surface;
    uint32_t diu_fast_background;
    unsigned diu_fast_plane, diu_fast_width, diu_fast_height;
    bool diu_fast_valid;
    uint32_t diu_status;
    uint32_t mbx_regs[2048];
    bool mbx_unimplemented[4096];
    bool mbx_pb_initialized;
    bool mbx_pb_free[8192];
    uint32_t mbx_pb_first, mbx_pb_last, mbx_pb_free_count;
    SmegNFC nfc;
    CharBackend serial;
    CharBackend bluetooth;
    bool bluetooth_attached;
    SmegHciUart hci;
    QEMUTimer *hci_tx_timer;
    qemu_irq external_irq;
    uint8_t regs[IMMR_SIZE];
    uint64_t dma_pending;
    bool psc_tx_enabled[12];
    bool psc_rx_enabled[12];
    uint8_t rx_fifo[1024];
    unsigned rx_head, rx_count;
    QEMUTimer *uart_tx_timer;
    int64_t uart_tx_deadline_ns;
    uint8_t uart_tx_fifo[4096];
    unsigned uart_tx_head, uart_tx_count;
    uint32_t uart_tx_isr;
    bool nfc_irq_level;
    bool usb_irq_level;
    bool sdhc_irq_level;
    bool sdhc_dma_level;
    bool usb_host_enabled;
    QEMUTimer *bench_net_timer;
    uint8_t bench_net_payload[SMEG_BENCH_NET_COUNT][8];
    int64_t bench_net_next_ns[SMEG_BENCH_NET_COUNT];
    uint16_t bench_net_valid;
    bool bench_clock_live;
    uint64_t bluetooth_tx_count;
    uint8_t bluetooth_tx_prefix[256];
    unsigned bluetooth_tx_prefix_len;
    bool bench_ecu_enabled;
    bool bench_key_profile;
    bool bench_esp_enabled;
    SmegBenchAlert bench_alert;
    bool trace_io;
    bool trace_uart;
    bool trace_spi;
    bool trace_mcu;
    bool trace_touch;
    uint8_t spi_tx[4096];
    unsigned spi_tx_count;
    uint8_t spi_rx[4096], spi_reply[92];
    unsigned spi_rx_head, spi_rx_count;
    bool spi_reply_valid, dma_servicing;
    uint64_t dma_requests;
    bool dma_reported[64];
    SmegMcuPeer mcu;
    bool sdhc_clock_running;
    QEMUPutMouseEntry *touch_mouse;
    QEMUTimer *touch_timer;
    uint16_t touch_x, touch_y;
    bool touch_down;
} SmegMachineState;

OBJECT_DECLARE_SIMPLE_TYPE(SmegMachineState, SMEG_MACHINE)

static void smeg_bench_net_tick(void *opaque);
static void smeg_bench_alert_queue(SmegMachineState *s, unsigned pointer);
static void smeg_sdhc_dma_requests(SmegMachineState *s);

static bool smeg_bench_config(const char *name, uint8_t value[16])
{
    const char *text = g_getenv(name);
    if (!text || !*text) {
        return false;
    }
    if (strlen(text) != 32) {
        error_report("%s requires exactly32 hexadecimal digits", name);
        exit(EXIT_FAILURE);
    }
    for (unsigned i = 0; i < 16; i++) {
        int hi = g_ascii_xdigit_value(text[2 * i]);
        int lo = g_ascii_xdigit_value(text[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            error_report("%s requires hexadecimal virtual configuration", name);
            exit(EXIT_FAILURE);
        }
        value[i] = (hi << 4) | lo;
    }
    warn_report("%s supplies explicit virtual MCU state; not measured car data", name);
    return true;
}

static bool smeg_sync_bench_led(SmegMachineState *s)
{
    if ((s->bench_net_valid & 0x80) &&
        smeg_bench_led_sync(s->bench_net_payload[7], s->bench_net_payload[0],
                            s->bench_net_payload[1], s->bench_net_valid)) {
        s->bench_net_next_ns[7] = 0;
        return true;
    }
    return false;
}

static bool smeg_shadow_register(hwaddr off, unsigned size)
{
    return (off >= 0xc00 && off + size <= 0xd00) ||
           (off >= 0xc0 && off + size <= 0xc4) ||
           (off >= 0x104 && off + size <= 0x108) ||
           (off >= 0xf00 && off + size <= 0xf80) ||
           (off >= 0x1100 && off + size <= 0x111c) ||
           (off >= 0x2100 && off + size <= 0x2174) ||
           (off >= 0x4000 && off + size <= 0x4300) ||
           (off >= 0x11000 && off + size <= 0x12000) ||
           (off >= 0x14000 && off + size <= 0x16000);
}

static uint64_t smeg_reg_get(SmegMachineState *s, hwaddr off, unsigned size)
{
    uint64_t value = 0;
    unsigned i;
    for (i = 0; i < size; i++) {
        value = (value << 8) | s->regs[off + i];
    }
    return value;
}

static void smeg_reg_put(SmegMachineState *s, hwaddr off, uint64_t value,
                         unsigned size)
{
    unsigned i;
    for (i = 0; i < size; i++) {
        s->regs[off + size - 1 - i] = value & 0xff;
        value >>= 8;
    }
}

/* MPC5121ERM 31.2.1: SIZE counts words; COUNT and ALARM count bytes.
 * The native console is configured for 115200 baud, 8N1. Preserve real
 * occupancy until each character finishes its ten wire bits, rather than
 * reporting an infinitely fast sink and repeatedly interrupting tyITx. */
#define SMEG_UART_BYTE_NS 86806
static unsigned smeg_uart_tx_capacity(SmegMachineState *s)
{
    return MIN((smeg_reg_get(s, 0x1199c, 4) & 0x7ff) * 4,
               sizeof(s->uart_tx_fifo));
}

static uint32_t smeg_uart_tx_status(SmegMachineState *s)
{
    unsigned capacity = smeg_uart_tx_capacity(s);
    return (!capacity ? 0x80 : 0) |
           (!s->uart_tx_count ? 1 : 0x20) |
           (capacity && s->uart_tx_count >= capacity ? 2 : 0) |
           (s->uart_tx_count < smeg_reg_get(s, 0x11984, 4) ? 4 : 0);
}

static void smeg_uart_tx_latch(SmegMachineState *s)
{
    s->uart_tx_isr |= smeg_uart_tx_status(s) & 0x7f;
}

static unsigned smeg_hci_capacity(SmegMachineState *s)
{
    return MIN((smeg_reg_get(s, 0x1119c, 4) & 0x7ff) * 4, SMEG_HCI_FIFO);
}

static void smeg_hci_latch(SmegMachineState *s)
{
    s->hci.tx_isr |= smeg_hci_tx_status(&s->hci, smeg_hci_capacity(s),
                                      smeg_reg_get(s, 0x11184, 4));
}

static uint32_t smeg_fifo_pending(SmegMachineState *s)
{
    uint32_t pending = 0;
    unsigned port;
    for (port = 0; port < 12; port++) {
        hwaddr base = 0x11000 + port * 0x100;
        if (s->psc_tx_enabled[port] &&
            (smeg_reg_get(s, base + 0x80, 4) & 1) &&
            (port == 1 && s->bluetooth_attached ?
                (s->hci.tx_isr & smeg_reg_get(s, base + 0x90, 4)) :
             port == 9 ? (s->uart_tx_isr &
                          smeg_reg_get(s, base + 0x90, 4)) :
             (smeg_reg_get(s, base + 0x84, 4) > 0 &&
              (smeg_reg_get(s, base + 0x90, 4) & 4)))) {
            /* PSC9 has timed FIFO occupancy and latched TX events. */
            /* MPC5121ERM Fig31-12: TX low half, RX high half. */
            pending |= 1U << port;
        }
        if (port == 1 && s->bluetooth_attached && s->psc_rx_enabled[1] &&
            (smeg_reg_get(s, base + 0xc0, 4) & 1) &&
            s->hci.rn > smeg_reg_get(s, base + 0xc4, 4) &&
            (smeg_reg_get(s, base + 0xd0, 4) & 4)) {
            pending |= 1U << 17;
        }
        if (port == 9 && s->psc_rx_enabled[port] &&
            (smeg_reg_get(s, base + 0xc0, 4) & 1) &&
            s->rx_count > smeg_reg_get(s, base + 0xc4, 4) &&
            (smeg_reg_get(s, base + 0xd0, 4) & 4)) {
            pending |= 1U << (port + 16);
        }
    }
    return pending;
}

static unsigned smeg_irq_vector(SmegMachineState *s)
{
    if (s->dma_pending && (smeg_reg_get(s, 0xc24, 4) & 0x40000000)) {
        return 65;
    }
    if ((s->diu_status & ~smeg_reg_get(s, 0x2148, 4) & 0x3f) &&
        (smeg_reg_get(s, 0xc24, 4) & 0x80000000)) {
        return 64;
    }
    if (s->nfc_irq_level && (smeg_reg_get(s, 0xc20, 4) & 0x00000400)) {
        return 6;
    }
    if (smeg_fifo_pending(s) && (smeg_reg_get(s, 0xc20, 4) & 0x00800000)) {
        return 40;
    }
    /* BSP IPIC input record0079f18c routes vxbPlbUsbEhci0 to source44. */
    if (s->usb_irq_level && (smeg_reg_get(s, 0xc20, 4) & 0x00080000)) {
        return 44;
    }
    if (s->sdhc_irq_level && (smeg_reg_get(s, 0xc20, 4) & 0x00000100)) {
        return 8;
    }
    return 0;
}

static void smeg_update_irq(SmegMachineState *s)
{
    /* Linux mpc512x_dma.c/IPIC source table: source65 -> low bit30.
     * This source is level-triggered and acknowledged by the DMA device. */
    uint32_t pending = (s->dma_pending ? 0x40000000 : 0) |
                      ((s->diu_status & ~smeg_reg_get(s, 0x2148, 4) & 0x3f)
                       ? 0x80000000 : 0);
    smeg_reg_put(s, 0xc0c, pending, 4);
    smeg_reg_put(s, 0xc08, (smeg_fifo_pending(s) ? 0x00800000 : 0) |
                 (s->usb_irq_level ? 0x00080000 : 0) |
                 (s->sdhc_irq_level ? 0x00000100 : 0) |
                 (s->nfc_irq_level ? 0x00000400 : 0), 4);
    qemu_set_irq(s->external_irq, smeg_irq_vector(s) != 0);
}

static void smeg_usb_irq(void *opaque, int line, int level)
{
    SmegMachineState *s = opaque;
    s->usb_irq_level = level;
    smeg_update_irq(s);
}

static void smeg_sdhc_irq(void *opaque, int line, int level)
{
    SmegMachineState *s = opaque;
    s->sdhc_irq_level = level;
    smeg_update_irq(s);
}

static void smeg_sdhc_dma_irq(void *opaque, int line, int level)
{
    SmegMachineState *s = opaque;
    s->sdhc_dma_level = level;
    if (level) { smeg_sdhc_dma_requests(s); }
}

/* Generic EHCI with the offset layout needed by this BSP. The QEMU Tegra
 * parent is reused for its caps100/opregs140 layout, not a Tegra SoC model.
 * One embedded high-speed root port is sufficient for the bench media disk. */
static void smeg_usb_class_init(ObjectClass *oc, void *data)
{
    SYS_BUS_EHCI_CLASS(oc)->portnr = 1;
}

static const TypeInfo smeg_usb_type = {
    .name = "smeg-usb-ehci",
    .parent = TYPE_TEGRA2_EHCI,
    .class_init = smeg_usb_class_init,
};

#include "smeg_diu.h"

static void smeg_present_frame(void *opaque)
{
    SmegMachineState *s = opaque;
    /* Host display publication only; guest DIU vblank timing and IRQ remain
     * on the panel timer. Main-loop BH keeps all console work off the vCPU. */
    graphic_hw_update(s->diu_console);
    if (s->trace_touch) {
        int64_t published_ns=qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
        DisplaySurface *surface=qemu_console_surface(s->diu_console);
        GChecksum *hash=g_checksum_new(G_CHECKSUM_SHA256);
        if (surface_width(surface)==800 && surface_height(surface)==480 &&
            surface_bits_per_pixel(surface)==32) {
            /* Match the measured menu ROI; exclude clock/status animations.
             * Hash after publication so timing includes real scanout work. */
            for (unsigned y=80;y<450;y++) {
                g_checksum_update(hash,surface_data(surface)+
                                  y*surface_stride(surface),800*4);
            }
        }
        qemu_log_mask(LOG_UNIMP, "SMEG display publish host_ns=%" PRId64
                      " roi_sha256=%s\n",published_ns,g_checksum_get_string(hash));
        g_checksum_free(hash);
    }
}

static void smeg_frame_ready(void *opaque)
{
    SmegMachineState *s = opaque;
    qemu_bh_schedule(s->diu_present_bh);
}

static uint32_t smeg_software_framebuffer(void *opaque)
{
    SmegMachineState *s = opaque;
    for (unsigned plane = 0; plane < 3; plane++) {
        uint32_t descriptor = smeg_reg_get(s, 0x2100 + plane * 4, 4);
        uint8_t ad[40];
        if (!descriptor || (uint64_t)descriptor + sizeof(ad) > MACHINE(s)->ram_size ||
            address_space_read(&address_space_memory, descriptor,
                               MEMTXATTRS_UNSPECIFIED, ad, sizeof(ad)) != MEMTX_OK) {
            continue;
        }
        uint32_t format = ldl_le_p(ad), bitmap = ldl_le_p(ad + 4);
        if (format == 0x06338888 && ldl_le_p(ad + 8) == 0x001e0320 &&
            ldl_le_p(ad + 12) == 0x01e00320 && bitmap &&
            (uint64_t)bitmap + 800 * 480 * 4 <= MACHINE(s)->ram_size) {
            return bitmap;
        }
    }
    return 0;
}

static void smeg_nfc_irq_changed(void *opaque, bool level)
{
    SmegMachineState *s = opaque;
    s->nfc_irq_level = level;
    smeg_update_irq(s);
}

static void smeg_uart_tx_drain(void *opaque)
{
    SmegMachineState *s = opaque;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    if (!s->uart_tx_count || !s->psc_tx_enabled[9]) {
        s->uart_tx_deadline_ns = 0;
        timer_del(s->uart_tx_timer);
        return;
    }
    if (!s->uart_tx_deadline_ns) {
        s->uart_tx_deadline_ns = now + SMEG_UART_BYTE_NS;
    }
    if (now >= s->uart_tx_deadline_ns) {
        uint64_t elapsed = 1 + (now - s->uart_tx_deadline_ns) /
                                  SMEG_UART_BYTE_NS;
        unsigned due = MIN(elapsed, s->uart_tx_count);
        uint8_t completed[sizeof(s->uart_tx_fifo)];
        /* Catch up only wire time belonging to this nonempty FIFO. Late
         * main-loop timer service must not turn115200baud into10bytes/sec.
         * Latch each intervening FIFO condition, then publish in one batch. */
        for (unsigned i = 0; i < due; i++) {
            completed[i] = s->uart_tx_fifo[s->uart_tx_head];
            s->uart_tx_head = (s->uart_tx_head + 1) % sizeof(s->uart_tx_fifo);
            s->uart_tx_count--;
            smeg_uart_tx_latch(s);
        }
        s->uart_tx_deadline_ns += (int64_t)due * SMEG_UART_BYTE_NS;
        qemu_chr_fe_write_all(&s->serial, completed, due);
        smeg_update_irq(s);
    }
    if (s->uart_tx_count) {
        timer_mod(s->uart_tx_timer, s->uart_tx_deadline_ns);
    } else {
        /* An empty/disabled transmitter accrues no credit for later data. */
        s->uart_tx_deadline_ns = 0;
        timer_del(s->uart_tx_timer);
    }
}

static void smeg_uart_tx_sync(SmegMachineState *s)
{
    if (s->psc_tx_enabled[9] && s->uart_tx_count &&
        s->uart_tx_deadline_ns &&
        qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) >= s->uart_tx_deadline_ns) {
        smeg_uart_tx_drain(s);
    }
}

static void smeg_uart_tx_write(SmegMachineState *s, uint8_t ch)
{
    unsigned capacity = smeg_uart_tx_capacity(s);
    smeg_uart_tx_sync(s);
    if (!capacity || s->uart_tx_count >= capacity) {
        s->uart_tx_isr |= 0x10; /* Genuine FIFO write overrun. */
    } else {
        bool was_empty = !s->uart_tx_count;
        s->uart_tx_fifo[(s->uart_tx_head + s->uart_tx_count) %
                       sizeof(s->uart_tx_fifo)] = ch;
        s->uart_tx_count++;
        smeg_uart_tx_latch(s);
        if (was_empty && s->psc_tx_enabled[9]) {
            s->uart_tx_deadline_ns =
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + SMEG_UART_BYTE_NS;
            timer_mod(s->uart_tx_timer, s->uart_tx_deadline_ns);
        }
    }
    smeg_update_irq(s);
}

static int smeg_serial_can_receive(void *opaque)
{
    SmegMachineState *s = opaque;
    return sizeof(s->rx_fifo) - s->rx_count;
}

static void smeg_serial_receive(void *opaque, const uint8_t *buf, int size)
{
    SmegMachineState *s = opaque;
    for (int i = 0; i < size && s->rx_count < sizeof(s->rx_fifo); i++) {
        s->rx_fifo[(s->rx_head + s->rx_count) % sizeof(s->rx_fifo)] = buf[i];
        s->rx_count++;
    }
    if (s->trace_uart) {
        qemu_log_mask(LOG_UNIMP,
                      "SMEG UART RX received=%d queued=%u enabled=%u "
                      "slice=%08" PRIx64 " mask=%08" PRIx64
                      " alarm=%" PRIu64 " ipicmask=%08" PRIx64 "\n",
                      size, s->rx_count, s->psc_rx_enabled[9],
                      smeg_reg_get(s, 0x119c0, 4),
                      smeg_reg_get(s, 0x119d0, 4),
                      smeg_reg_get(s, 0x119c4, 4),
                      smeg_reg_get(s, 0xc20, 4));
    }
    smeg_update_irq(s);
}

static uint8_t smeg_serial_rx_byte(SmegMachineState *s)
{
    uint8_t ch = 0;
    if (s->rx_count) {
        ch = s->rx_fifo[s->rx_head];
        s->rx_head = (s->rx_head + 1) % sizeof(s->rx_fifo);
        s->rx_count--;
        if (s->trace_uart) {
            qemu_log_mask(LOG_UNIMP,
                          "SMEG UART RX pop=%02x remaining=%u\n",
                          ch, s->rx_count);
        }
    }
    smeg_update_irq(s);
    qemu_chr_fe_accept_input(&s->serial);
    return ch;
}

/* PSC1 H4 transport. Nonblocking writes retain unsent bytes, and RX
 * asserts the real FIFO/IPIC interrupt immediately. No HCI opcodes are
 * fabricated in the board. Only an explicitly attached chardev enables it. */
static void smeg_hci_drain(void *opaque)
{
    SmegMachineState *s = opaque;
    if (!s->bluetooth_attached || !s->psc_tx_enabled[1] || !s->hci.tn) return;
    unsigned n = MIN(s->hci.tn, SMEG_HCI_FIFO - s->hci.th);
    /* Transport pacing is a conservative 115200-baud batch per millisecond;
     * UART divisor/Infineon baud-switch timing remains an approximation. */
    n = MIN(n, 12U);
    int sent = qemu_chr_fe_write(&s->bluetooth, s->hci.tx + s->hci.th, n);
    if (sent > 0) smeg_hci_sent(&s->hci, sent);
    smeg_hci_latch(s);
    smeg_update_irq(s);
    if (s->hci.tn) timer_mod(s->hci_tx_timer,
                         qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 1000000);
}

static int smeg_hci_can_receive(void *opaque)
{
    SmegMachineState *s = opaque;
    return s->psc_rx_enabled[1] ? SMEG_HCI_FIFO - s->hci.rn : 0;
}

static void smeg_hci_receive_bytes(void *opaque, const uint8_t *data, int n)
{
    SmegMachineState *s = opaque;
    smeg_hci_receive(&s->hci, data, n);
    smeg_update_irq(s);
}

static uint8_t smeg_hci_read_byte(SmegMachineState *s)
{
    uint8_t b = smeg_hci_read(&s->hci);
    smeg_update_irq(s);
    qemu_chr_fe_accept_input(&s->bluetooth);
    return b;
}

/* Virtual single-contact front panel: host pointer coordinates become real
 * MCU tactile notifications and traverse the unmodified native TS controller.
 * That controller consumes an800x800 frame, pressure, and a16bit timestamp;
 * retain its calibration/debounce instead of calling Qt or guest functions.
 * Native Kbd_Write002616a8 selects channel08; UpdateData0128c6d4 handles
 * message80 and GetTactileData0128bc64 decodes packedXY. Its flagsbit7 marks
 * a recent press; raw samples retain bit0 for the native begin filter.
 * Native DeBounceEnd/timer synthesizes final release flags downstream.
 * Pressure128 and 50Hz sampling are explicit single-contact bench fixtures. */
#define SMEG_TOUCH_SAMPLE_NS 20000000
static void smeg_spi_dma_requests(SmegMachineState *s);
static void smeg_touch_sample(SmegMachineState *s)
{
    uint16_t ms = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) / 1000000;
    int accepted = smeg_mcu_peer_touch(&s->mcu, s->touch_x, s->touch_y,
                                      s->touch_down ? 128 : 0, ms,
                                      s->touch_down ? 0x81 : 0x01);
    if (!accepted && s->trace_touch) {
        qemu_log_mask(LOG_UNIMP, "SMEG touch queue full ms=%u count=%u\n",
                      ms, s->mcu.touch_count);
    }
    /* A host RX descriptor may already be armed. Only complete it when its
     * real pending MCU response can carry the newly arrived notification.
     * Never invent an unsolicited transfer or bypass the native SPI task. */
    if (s->spi_reply_valid &&
        smeg_mcu_peer_touch_pending(&s->mcu, s->spi_reply)) {
        smeg_spi_dma_requests(s);
    }
}

static void smeg_touch_timer(void *opaque)
{
    SmegMachineState *s = opaque;
    if (!s->touch_down) {
        return;
    }
    smeg_touch_sample(s);
    timer_mod(s->touch_timer,
              qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + SMEG_TOUCH_SAMPLE_NS);
}

static void smeg_touch_mouse(void *opaque, int x, int y, int z, int buttons)
{
    SmegMachineState *s = opaque;
    bool down = (buttons & MOUSE_EVENT_LBUTTON) != 0;
    bool changed = down != s->touch_down;
    (void)z; /* Wheel/right button have no invented vehicle meaning. */
    s->touch_x = ((uint64_t)CLAMP(x, 0, 32767) * 799 + 16383) / 32767;
    unsigned screen_y = ((uint64_t)CLAMP(y, 0, 32767) * 479 + 16383) / 32767;
    /* Native tslib ts_read0158a7b4 maps Y=(800-rawY)*480/800.
     * Invert that real driver transform, not an assumed 4095 ADC scale.
     * TS RejectBeginXY limits raw coordinates to799, so the top edge uses
     * nearest representable rawY799 (native pixelY0 after truncation). */
    s->touch_y = MIN(799, 800 - (screen_y * 800 + 240) / 480);
    s->touch_down = down;
    if (changed) {
        qemu_log_mask(LOG_UNIMP,
                      "SMEG touch host %s x=%u y=%u via native MCU\n",
                      down ? "down" : "up", s->touch_x, s->touch_y);
        if (s->trace_touch) {
            qemu_log_mask(LOG_UNIMP,
                          "SMEG touch edge down=%u host_ns=%" PRId64
                          " virtual_ns=%" PRId64 " queued=%u\n",
                          down, qemu_clock_get_ns(QEMU_CLOCK_REALTIME),
                          qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
                          s->mcu.touch_count);
        }
        smeg_touch_sample(s);
        if (down) {
            timer_mod(s->touch_timer,
                      qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + SMEG_TOUCH_SAMPLE_NS);
        } else {
            /* Deliver the real edge once, then stop contact sampling. The
             * original DeBounceEnd0157ed4c restarts its watchdog for every
             * accepted point. Artificial zero-pressure repeats at20/40/60ms
             * postponed native release instead of improving its filtering. */
            timer_del(s->touch_timer);
        }
    }
}

static void smeg_spi_shift(SmegMachineState *s)
{
    bool idle = true;
    uint8_t response[92];
    if (!s->spi_tx_count || !s->psc_tx_enabled[5]) {
        return;
    }
    if (s->spi_tx_count != 92) {
        qemu_log_mask(LOG_UNIMP, "SMEG SPI unsupported frame bytes=%u\n",
                      s->spi_tx_count);
        return;
    }
    for (unsigned i = 0; i < 92; i++) {
        idle &= s->spi_tx[i] == 0xff;
    }
    memset(response, 0xff, sizeof(response));
    if (idle) {
        /* Master read clocks use 0xff dummy TX. The secondary MCU supplies
         * the response prepared after the preceding complete host frame. */
        if (s->spi_reply_valid) {
            memcpy(response, s->spi_reply, sizeof(response));
            s->spi_reply_valid = false;
        }
    } else {
        s->mcu.bench_ecu_mask = s->bench_ecu_enabled ?
            ((s->bench_net_valid & 3) |
             ((s->bench_net_valid & 0x30) == 0x30 ? 4 : 0)) : 0;
        s->spi_reply_valid = smeg_mcu_peer_exchange(&s->mcu, s->spi_tx,
                                                    s->spi_reply);
        unsigned changed = smeg_bench_ecu_apply(&s->mcu, s->bench_net_payload,
                                                s->bench_net_valid);
        if (smeg_bench_body_apply(&s->mcu, s->bench_net_payload[4],
                                 (s->mcu.bench_ecu_mask & 4) != 0)) {
            changed |= 0x10;
        }
        if (changed) {
            if (smeg_sync_bench_led(s)) {
                smeg_mcu_peer_net(&s->mcu, 0x22, s->bench_net_payload[7], 5);
            }
            if (changed & 1) {
                smeg_mcu_peer_net(&s->mcu, 0x1a, s->bench_net_payload[0], 5);
                smeg_bench_alert_queue(s,
                    (s->bench_net_payload[0][3] >> 6) == 2 ? 545 : 544);
            }
            if (changed & 2) {
                smeg_mcu_peer_net(&s->mcu, 5, s->bench_net_payload[1], 8);
            }
            if (changed & 0x10) {
                smeg_mcu_peer_net(&s->mcu, 0x0f, s->bench_net_payload[4], 7);
            }
            if (s->spi_reply_valid) {
                smeg_mcu_peer_net_pending(&s->mcu, s->spi_reply);
            }
            qemu_log_mask(LOG_UNIMP,
                "SMEG bench ECU response changed=%u ECOstatus=%u parkingRear=%u WelcomeLighting=%u (simulated only)\n",
                changed, s->bench_net_payload[0][3] >> 6,
                s->bench_net_payload[1][0] >> 5,
                (s->bench_net_payload[4][3] >> 3) & 1);
        }
        if (s->trace_mcu || !s->spi_reply_valid) {
            qemu_log_mask(LOG_UNIMP,
                          "SMEG virtual MCU host=%02x bytes=92 valid=%u "
                          "reply=%02x identity=%02x%02x%02x%02x\n", s->spi_tx[0],
                          s->spi_reply_valid, s->spi_reply[0],
                          s->mcu.identity[0],s->mcu.identity[1],
                          s->mcu.identity[2],s->mcu.identity[3]);
        }
        if (s->trace_mcu && s->spi_tx[0] == 0xaa && s->spi_tx[1]) {
            char hex[185];
            for (unsigned i = 0; i < 92; i++)
                snprintf(hex + 2*i, 3, "%02x", s->spi_tx[i]);
            qemu_log_mask(LOG_UNIMP, "SMEG MCU frame_tx %s\n", hex);
        }
        /* The observed transport writes a complete host frame, resets its
         * RX FIFO, then arms receive DMA without dummy TX clocks. Retain the
         * secondary-MCU response until that receive phase instead of losing
         * it as full-duplex filler during the preceding write phase. */
        s->spi_tx_count = 0;
        return;
    }
    for (unsigned i = 0; i < 92; i++) {
        if (s->spi_rx_count < sizeof(s->spi_rx)) {
            s->spi_rx[(s->spi_rx_head + s->spi_rx_count) %
                      sizeof(s->spi_rx)] = response[i];
            s->spi_rx_count++;
        }
    }
    s->spi_tx_count = 0;
}

static uint8_t smeg_spi_rx_byte(SmegMachineState *s)
{
    uint8_t value = 0xff;
    if (s->spi_rx_count) {
        value = s->spi_rx[s->spi_rx_head];
        s->spi_rx_head = (s->spi_rx_head + 1) % sizeof(s->spi_rx);
        s->spi_rx_count--;
    }
    return value;
}

static int smeg_dma_read_memory(void *opaque, uint32_t address,
                                uint8_t *buffer, unsigned size)
{
    return address_space_read(&address_space_memory, address,
                              MEMTXATTRS_UNSPECIFIED, buffer, size) != MEMTX_OK;
}

static int smeg_dma_write_memory(void *opaque, uint32_t address,
                                 const uint8_t *buffer, unsigned size)
{
    return address_space_write(&address_space_memory, address,
                               MEMTXATTRS_UNSPECIFIED, buffer, size) != MEMTX_OK;
}

static void smeg_dma_start(SmegMachineState *s, unsigned channel)
{
    hwaddr tcd = 0x15000 + channel * 32;
    uint32_t source = smeg_reg_get(s, tcd, 4);
    uint16_t attr = smeg_reg_get(s, tcd + 4, 2);
    int16_t soff = smeg_reg_get(s, tcd + 6, 2);
    uint32_t nbytes = smeg_reg_get(s, tcd + 8, 4);
    int32_t slast = smeg_reg_get(s, tcd + 12, 4);
    uint32_t dest = smeg_reg_get(s, tcd + 16, 4);
    uint16_t count = smeg_reg_get(s, tcd + 20, 2);
    int16_t doff = smeg_reg_get(s, tcd + 22, 2);
    int32_t dlast = smeg_reg_get(s, tcd + 24, 4);
    uint16_t csr = smeg_reg_get(s, tcd + 30, 2);
    unsigned ssize = 1U << ((attr >> 8) & 7);
    unsigned dsize = 1U << (attr & 7);
    unsigned minor;
    g_autofree uint8_t *buffer = NULL;

    if ((source == 0x80001538 || dest == 0x80001538) && !s->sdhc_dma_level) {
        return; /* Armed hardware request; wait for actual card data readiness. */
    }

    /* Non-linked BSP descriptors, including real SD4-byte/RAM32-byte bursts. */
    if (!count || (count & 0x8000) || (csr & 0x10) ||
        !nbytes || nbytes % ssize || nbytes % dsize ||
        (uint64_t)nbytes * count > 32 * MiB) {
        qemu_log_mask(LOG_UNIMP,
                      "SMEG DMA unsupported TCD ch=%u attr=%04x csr=%04x "
                      "nbytes=%u citer=%u\n", channel, attr, csr,
                      nbytes, count);
        return;
    }
    buffer = g_malloc(nbytes);
    if (!s->dma_reported[channel] &&
        (source == 0x800115fc || dest == 0x800115bc)) {
        uint64_t elements = (uint64_t)nbytes * count / ssize;
        int64_t last_dest = (int64_t)dest +
                            ((int64_t)elements - 1) * doff;
        qemu_log_mask(LOG_UNIMP,
                      "SMEG SPI DMA physical extent ch=%u attr=%04x "
                      "src=%08x soff=%d slast=%d dst=%08x doff=%d "
                      "dlast=%d nbytes=%u count=%u element=%u "
                      "write_min=%08" PRIx64 " write_max=%08" PRIx64 "\n",
                      channel, attr, source, soff, slast, dest, doff, dlast,
                      nbytes, count, ssize,
                      (uint64_t)MIN((int64_t)dest, last_dest),
                      (uint64_t)MAX((int64_t)dest, last_dest) + dsize - 1);
        s->dma_reported[channel] = true;
    }
    if (s->trace_io) {
        qemu_log_mask(LOG_UNIMP,
                  "SMEG DMA start ch=%u source=%08x dest=%08x "
                  "nbytes=%u count=%u\n", channel, source, dest, nbytes, count);
    }
    for (minor = 0; minor < count; minor++) {
        if (smeg_dma_copy_minor(s, &source, &dest, ssize, dsize, soff, doff,
                                nbytes, buffer, smeg_dma_read_memory,
                                smeg_dma_write_memory)) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "SMEG DMA bus error ch=%u src=%08x dst=%08x\n",
                          channel, source, dest);
            return;
        }
    }
    if (s->trace_touch && smeg_reg_get(s, tcd, 4) == 0x800115fc &&
        (uint64_t)nbytes * count == 92) {
        uint8_t frame[92];
        uint32_t start_dest = smeg_reg_get(s, tcd + 16, 4);
        if (address_space_read(&address_space_memory, start_dest,
                               MEMTXATTRS_UNSPECIFIED, frame, sizeof(frame)) ==
            MEMTX_OK && frame[0] == 0x99 && smeg_mcu_crc_valid(frame, 90)) {
            unsigned pos = 2;
            for (unsigned i = 0; i < frame[1] && pos + 5 <= 90; i++) {
                unsigned length = frame[pos + 2];
                if (pos + length + 5 > 90) {
                    break;
                }
                if (frame[pos] == 8 && frame[pos + 1] == 0x80 && length == 7) {
                    unsigned sample_ms = ((unsigned)frame[pos + 7] << 8) |
                                         frame[pos + 8];
                    unsigned now_ms = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) /
                                      1000000;
                    qemu_log_mask(LOG_UNIMP,
                                  "SMEG touch DMA down=%u sample_ms=%u "
                                  "age_ms=%u host_ns=%" PRId64
                                  " virtual_ns=%" PRId64 " queued=%u\n",
                                  frame[pos + 6] != 0, sample_ms,
                                  (now_ms - sample_ms) & 0xffff,
                                  qemu_clock_get_ns(QEMU_CLOCK_REALTIME),
                                  qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
                                  s->mcu.touch_count);
                }
                pos += length + 5;
            }
        }
    }
    source += slast;
    dest += dlast;
    smeg_reg_put(s, tcd, source, 4);
    smeg_reg_put(s, tcd + 16, dest, 4);
    smeg_reg_put(s, tcd + 20, 0, 2);
    smeg_reg_put(s, tcd + 30, (csr & ~0x41) | 0x80, 2);
    if (csr & 2) { /* INTMAJOR */
        s->dma_pending |= UINT64_C(1) << channel;
        smeg_update_irq(s);
    }
    if (s->trace_io) {
        qemu_log_mask(LOG_UNIMP, "SMEG DMA complete ch=%u irq=%u\n",
                      channel, !!(csr & 2));
    }
}

static void smeg_sdhc_dma_requests(SmegMachineState *s)
{
    if (s->dma_servicing || !s->sdhc_dma_level) { return; }
    s->dma_servicing = true;
    for (unsigned ch = 0; ch < 64 && s->sdhc_dma_level; ch++) {
        hwaddr tcd = 0x15000 + ch * 32;
        uint32_t src = smeg_reg_get(s, tcd, 4);
        uint32_t dst = smeg_reg_get(s, tcd + 16, 4);
        if ((s->dma_requests & (UINT64_C(1) << ch)) &&
            (src == 0x80001538 || dst == 0x80001538) &&
            smeg_reg_get(s, tcd + 20, 2)) {
            qemu_log_mask(LOG_UNIMP, "SMEG SD DMA request ch=%u src=%08x dst=%08x attr=%04x bytes=%u count=%u\n",
                          ch, src, dst, (unsigned)smeg_reg_get(s,tcd+4,2),
                          (unsigned)smeg_reg_get(s,tcd+8,4),
                          (unsigned)smeg_reg_get(s,tcd+20,2));
            smeg_dma_start(s, ch);
        }
    }
    s->dma_servicing = false;
}

static void smeg_spi_dma_requests(SmegMachineState *s)
{
    if (s->dma_servicing || !s->psc_tx_enabled[5]) {
        return;
    }
    s->dma_servicing = true;
    /* Service the SPI TX requests before RX: bytes are clocked full duplex
     * by the TX stream, then the receive DMA drains that stream's RX FIFO. */
    for (unsigned pass = 0; pass < 2; pass++) {
        for (unsigned ch = 0; ch < 64; ch++) {
            hwaddr tcd = 0x15000 + ch * 32;
            uint32_t src = smeg_reg_get(s, tcd, 4);
            uint32_t dst = smeg_reg_get(s, tcd + 16, 4);
            unsigned count = smeg_reg_get(s, tcd + 20, 2) & 0x7fff;
            uint32_t bytes = smeg_reg_get(s, tcd + 8, 4);
            bool tx = dst == 0x800115bc;
            bool rx = src == 0x800115fc;
            if (!(s->dma_requests & (UINT64_C(1) << ch)) || !count ||
                (pass == 0 ? !tx : !rx)) {
                continue;
            }
            if (rx && s->spi_rx_count == 0 && s->spi_reply_valid) {
                /* Virtual MCU now supplies its response on the externally
                 * clocked receive phase. FIFO reset does not discard data
                 * still waiting at the peer. No guest buffer is injected. */
                for (unsigned i = 0; i < sizeof(s->spi_reply); i++) {
                    s->spi_rx[(s->spi_rx_head + s->spi_rx_count) %
                              sizeof(s->spi_rx)] = s->spi_reply[i];
                    s->spi_rx_count++;
                }
                s->spi_reply_valid = false;
                if (s->trace_mcu) {
                    qemu_log_mask(LOG_UNIMP,
                                  "SMEG virtual MCU receive phase first=%02x "
                                  "bytes=%u\n", s->spi_reply[0], s->spi_rx_count);
                }
            }
            if (rx && (uint64_t)bytes * count > s->spi_rx_count) {
                continue;
            }
            if (s->trace_spi) {
                qemu_log_mask(LOG_UNIMP,
                              "SMEG SPI DMA ch=%u tx=%u src=%08x dst=%08x "
                              "nbytes=%u count=%u\n",
                              ch, tx, src, dst, bytes, count);
            }
            s->dma_requests &= ~(UINT64_C(1) << ch);
            smeg_dma_start(s, ch);
            if (tx) {
                smeg_spi_shift(s);
            }
        }
    }
    s->dma_servicing = false;
}

static uint64_t smeg_mmio_read(void *opaque, hwaddr off, unsigned size)
{
    SmegMachineState *s = opaque;
    uint64_t value = 0;
    hwaddr reg = off & 0xff;

    if (off >= 0x11900 && off < 0x11a00) {
        /* Polling-mode console checks TXEMPTY before writing the next byte.
         * Reflect wire time already elapsed even when main-loop timer service
         * is late; otherwise every single polled byte waits a host timeslice. */
        smeg_uart_tx_sync(s);
    }
    if (smeg_shadow_register(off, size)) {
        value = smeg_reg_get(s, off, size);
    }
    if (off == 0xc04 && size == 4) {
        value = smeg_irq_vector(s);
    } else if (off == 0x1108 && size == 4) {
        /* External USB overcurrent inputs are inactive HIGH on this bench.
         * Native UsbOvcWdg0x21e5d0 polls ioctl355/356: GPDAT bits20/7.
         * Drive only input pins; preserve GPDIR and the output data latch. */
        value |= (~smeg_reg_get(s, 0x1100, 4)) & 0x00100080U;
        /* Native gpioIoctl352 samples board straps DAT[10:8]. BSP256's
         * table at0079ff38 has index1 DB620PROTOC+ RAM512/Flash512 and
         * index4 MB810 INTEGRE RAM256/Flash256. BootRomStartup29a038
         * recognizes those two models as SMEG_PLUS_UPG; index0 DB600 PRS1
         * instead searches legacy SMEG_UPG (29a2e8). Select coherent virtual
         * PLUS boards, preserving output latches. Not measured car identity. */
        uint32_t strap_inputs = ~smeg_reg_get(s, 0x1100, 4) & 0x700U;
        uint32_t straps = s->nfc.nand_size == (512 * MiB / 2048) * (2048 + 64)
                          ? 0x100U : 0x400U;
        value = (value & ~strap_inputs) | (straps & strap_inputs);
    } else if (off == 0x2144 && size == 4) {
        value = s->diu_status;
        s->diu_status = 0;
        smeg_update_irq(s); /* NXP DIU INT_STATUS is read-to-clear. */
    } else if (off == 0x1500 && size == 4) {
        value = 0; /* START/STOP/RESET command bits read as zero. */
    } else if (off == 0x1504 && size == 4) {
        value = s->sdhc_clock_running ? 0x100 : 0;
    } else if (off == 0x11f04 && size == 4) {
        value = smeg_fifo_pending(s);
    } else if (off == 0x14020 && size == 4) {
        value = s->dma_pending >> 32;
    } else if (off == 0x14024 && size == 4) {
        value = s->dma_pending & UINT32_MAX;
    }
    if (off == 0xe00 && size == 4) {
        /* Synthesized strap: bus ~200 MHz, CPU multiplier 2. This is a
         * bring-up clock state derived from the local BSP's clock formula,
         * not a measured board RCW. */
        value = 0x05040000;
    }
    if (off >= 0x11000 && off < 0x11c00) {
        /* PSC status: TX empty and TX ready; no received data. */
        if (reg == 4 && size == 2) {
            /* MPC5121ERM Rev4 Fig30-7/Table30-7: PSC5 is SPI, whose
             * healthy core SR is zero. 0x0400/0x0100 are reserved here,
             * not MPC5200 UART TXRDY/RXRDY indications. Readiness lives
             * in the centralized FIFO SR/count registers below. Returning
             * 0x0400 made the native driver report every transfer as a
             * nonzero status and flood its NAND-backed upgrade log. */
            value = ((off >> 8 & 0xf) == 5 ? 0 : 0x0c00) |
                             ((off >> 8 & 0xf) == 9 && s->rx_count
                              ? 0x0100 : 0);
            if ((off >> 8 & 0xf) == 9) {
                value = (s->uart_tx_count ? 0 : 0x0800) |
                        (s->uart_tx_count < smeg_uart_tx_capacity(s) ? 0x400 : 0) |
                        (s->rx_count ? 0x100 : 0);
            }
        } else if ((reg == 0x88 || reg == 0x8c) && size == 4) {
            value = (off >> 8 & 0xf) == 9 ?
                    (reg == 0x88 ? smeg_uart_tx_status(s) : s->uart_tx_isr) :
                    (reg == 0x88 ? 5 : 4);
        } else if (reg == 0x94 && size == 4) {
            value = (off >> 8 & 0xf) == 9 ? s->uart_tx_count : 0;
        } else if (reg == 0xc8 && size == 4) {
            /* RX DATA READY bit5 is tested by the observed BSP ISR while
             * draining bytes; bit2 identifies the FIFO alarm condition. */
            value = (((off >> 8 & 0xf) == 9 && s->rx_count) ||
                     ((off >> 8 & 0xf) == 5 && s->spi_rx_count)) ? 0x24 : 1;
        } else if (reg == 0xcc && size == 4) {
            value = (off >> 8 & 0xf) == 5 ?
                    (s->spi_rx_count ? 0x24 : 1) :
                    (((off >> 8 & 0xf) == 9 && s->rx_count) ? 4 : 0);
        } else if (reg == 0xd4 && size == 4) {
            value = (off >> 8 & 0xf) == 9 ? s->rx_count :
                    ((off >> 8 & 0xf) == 5 ? s->spi_rx_count : 0);
        } else if (reg == 0xfc && (off >> 8 & 0xf) == 5) {
            value = 0;
            for (unsigned i = 0; i < size; i++) {
                value = (value << 8) | smeg_spi_rx_byte(s);
            }
        } else if ((reg == 0xfc || reg == 0x0c) &&
                   (off >> 8 & 0xf) == 9) {
            value = 0;
            for (unsigned i = 0; i < size; i++) {
                value = (value << 8) | smeg_serial_rx_byte(s);
            }
        }
    }
    if (s->bluetooth_attached && off >= 0x11100 && off < 0x11200) {
        if (reg == 4 && size == 2) {
            value = (!s->hci.tn ? 0x800 : 0) |
                    (s->hci.tn < smeg_hci_capacity(s) ? 0x400 : 0) |
                    (s->hci.rn ? 0x100 : 0);
        } else if (reg == 0x88 && size == 4) {
            value = smeg_hci_tx_status(&s->hci, smeg_hci_capacity(s),
                                      smeg_reg_get(s, 0x11184, 4));
        } else if (reg == 0x8c && size == 4) value = s->hci.tx_isr;
        else if (reg == 0x94 && size == 4) value = s->hci.tn;
        else if (reg == 0xc8 && size == 4) value = s->hci.rn ? 0x24 : 1;
        else if (reg == 0xcc && size == 4) value = s->hci.rn ? 4 : 0;
        else if (reg == 0xd4 && size == 4) value = s->hci.rn;
        else if (reg == 0xfc || (reg == 0x0c && size == 1)) {
            value = 0;
            for (unsigned i = 0; i < size; i++)
                value = (value << 8) | smeg_hci_read_byte(s);
        }
    }
    if (s->trace_io || (!smeg_shadow_register(off, size) && off != 0xe00 &&
                       off != 0x1500 && off != 0x1504) ||
        (s->trace_uart && ((off >= 0x11900 && off < 0x11a00) ||
                          off == 0x11f04 || (off == 0xc04 && value == 40))) ||
        (s->trace_spi && ((off >= 0x11500 && off < 0x11600) ||
                         (off >= 0x1100 && off < 0x111c)))) {
        qemu_log_mask(LOG_UNIMP,
                  "SMEG MMIO R pc=0x%08" PRIx64 " addr=0x%08"
                  HWADDR_PRIx " size=%u ->0x%" PRIx64 " (stub)\n",
                  (uint64_t)s->cpu->env.nip, (hwaddr)(IMMR_BASE + off),
                  size, value);
    }
    return value;
}

static void smeg_mmio_write(void *opaque, hwaddr off, uint64_t value,
                            unsigned size)
{
    SmegMachineState *s = opaque;
    uint32_t previous_gpio = off == 0x1108 && size == 4 ?
                             smeg_reg_get(s, 0x1108, 4) : 0;
    if (s->trace_io || (!smeg_shadow_register(off, size) && off != 0x1500) ||
        (s->trace_uart && off >= 0x11900 && off < 0x11a00) ||
        (s->trace_spi && ((off >= 0x11500 && off < 0x11600) ||
                         (off >= 0x1100 && off < 0x111c)))) {
        qemu_log_mask(LOG_UNIMP,
                  "SMEG MMIO W pc=0x%08" PRIx64 " addr=0x%08"
                  HWADDR_PRIx " size=%u value=0x%" PRIx64 " (stub)\n",
                  (uint64_t)s->cpu->env.nip, (hwaddr)(IMMR_BASE + off),
                  size, value);
    }
    if (smeg_shadow_register(off, size)) {
        smeg_reg_put(s, off, value, size);
    }
    /* Native sysToMonitor0020e3d0 requests board reset through gpioIoctl14,
     * asserting outputGPIO10000000 at0021c738. ConfigGpio leaves it low.
     * Treat that board request as a guest reset; no firmware PC interception. */
    if (off == 0x1108 && size == 4 && !(previous_gpio & 0x10000000U) &&
        (value & 0x10000000U) && (smeg_reg_get(s, 0x1100, 4) & 0x10000000U)) {
        qemu_log_mask(LOG_UNIMP, "SMEG native GPIO board reset request\n");
        qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
    }
    if (off == 0x2148 && size == 4) {
        smeg_update_irq(s);
    }
    if (off >= 0x11500 && off < 0x11600 &&
        ((off & 0xff) == 0xbc || (off & 0xff) == 0x0c)) {
        for (unsigned i = 0; i < size; i++) {
            uint8_t byte = value >> ((size - i - 1) * 8);
            if (s->spi_tx_count < sizeof(s->spi_tx)) {
                s->spi_tx[s->spi_tx_count++] = byte;
            }
            if (s->trace_spi) {
                qemu_log_mask(LOG_UNIMP,
                              "SMEG SPI TX byte=%02x index=%u\n",
                              byte, s->spi_tx_count);
            }
        }
    }
    if (off == 0x1500 && size == 4) {
        /* MPC5121ERM 34.3.2.1: only emulate the controller clock handshake,
         * not a card, card presence, command response or data transfer. */
        if ((value & 3) == 3) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "SMEG SDHC invalid simultaneous START/STOP\n");
        } else if (value & 9) {
            s->sdhc_clock_running = false;
        } else if (value & 2) {
            s->sdhc_clock_running = true;
        }
    }
    if (off == 0x1401e && size == 1) {
        /* SSRT software start; bit6 requests all channels, not implemented. */
        if (!(value & 0x40)) {
            smeg_dma_start(s, value & 0x3f);
        }
    } else if (off == 0x14018 && size == 1) {
        s->dma_requests |= UINT64_C(1) << (value & 0x3f);
        smeg_spi_dma_requests(s);
        smeg_sdhc_dma_requests(s);
    } else if (off == 0x14019 && size == 1) {
        s->dma_requests &= ~(UINT64_C(1) << (value & 0x3f));
    } else if (off == 0x1401c && size == 1) {
        /* CINT: clear interrupt(s). */
        s->dma_pending &= (value & 0x40) ? 0 :
                          ~(UINT64_C(1) << (value & 0x3f));
        smeg_update_irq(s);
    } else if (off == 0x1401f && size == 1) {
        hwaddr csr = 0x15000 + (value & 0x3f) * 32 + 30;
        smeg_reg_put(s, csr, smeg_reg_get(s, csr, 2) & ~0x80, 2);
    } else if ((off == 0xc24 || off == 0xc20) && size == 4) {
        smeg_update_irq(s);
    }
    if (off >= 0x11000 && off < 0x11c00) {
        unsigned port = (off - 0x11000) >> 8;
        hwaddr reg = off & 0xff;
        if (reg == 8 && size == 1) {
            if (value & 8) {
                s->psc_tx_enabled[port] = false;
            } else if (value & 4) {
                s->psc_tx_enabled[port] = true;
            }
            if (value & 2) {
                s->psc_rx_enabled[port] = false;
            } else if (value & 1) {
                s->psc_rx_enabled[port] = true;
            }
            if (port == 5 && (value & 4)) {
                smeg_spi_shift(s);
                smeg_spi_dma_requests(s);
            }
        }
        if (port == 5 && reg == 0x80 && size == 4 && (value & 0x80)) {
            s->spi_tx_count = 0;
        }
        if (port == 5 && reg == 0xc0 && size == 4 && (value & 0x80)) {
            s->spi_rx_head = s->spi_rx_count = 0;
        }
        if (port == 1 && s->bluetooth_attached) {
            if ((reg == 0xc0 && (value & 0x80)) ||
                (reg == 8 && (value & 0x70) == 0x20))
                s->hci.rh = s->hci.rn = 0;
            if ((reg == 0x80 && (value & 0x80)) ||
                (reg == 8 && (value & 0x70) == 0x30)) {
                s->hci.th = s->hci.tn = s->hci.tx_isr = 0;
                timer_del(s->hci_tx_timer);
            }
            if (reg == 0x8c) s->hci.tx_isr &= ~value;
            else smeg_hci_latch(s);
            if (reg == 8) {
                qemu_chr_fe_accept_input(&s->bluetooth);
                if (s->psc_tx_enabled[1] && s->hci.tn)
                    timer_mod(s->hci_tx_timer,
                        qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 1000000);
            }
        }
        if (port == 9) {
            if (reg == 0x8c && size == 4) {
                s->uart_tx_isr &= ~value; /* W1C, not a constant alarm. */
            } else if (reg == 0x80 && size == 4 && (value & 0x80)) {
                timer_del(s->uart_tx_timer);
                s->uart_tx_deadline_ns = 0;
                s->uart_tx_head = s->uart_tx_count = 0;
                s->uart_tx_isr = 0;
                smeg_uart_tx_latch(s);
            } else if (reg == 0x84 || reg == 0x9c || reg == 0x90 ||
                       reg == 0x80 || reg == 8) {
                smeg_uart_tx_latch(s);
            }
            if (reg == 8 && !s->psc_tx_enabled[9]) {
                timer_del(s->uart_tx_timer);
                s->uart_tx_deadline_ns = 0;
            } else if (reg == 8 && s->uart_tx_count &&
                       !timer_pending(s->uart_tx_timer)) {
                s->uart_tx_deadline_ns =
                    qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + SMEG_UART_BYTE_NS;
                timer_mod(s->uart_tx_timer, s->uart_tx_deadline_ns);
            }
        }
        smeg_update_irq(s);
    }
    /* Native HWAL port2 opens /tyCo/1 -> physical PSC1. Capture the
     * controller bootstrap without inventing controller/phone responses.
     * Prefix storage is bounded; the byte counter covers the whole stream. */
    if (off >= 0x11100 && off < 0x11200 &&
        ((off & 0xff) == 0xbc || ((off & 0xff) == 0x0c && size == 1))) {
        for (unsigned i = 0; i < size; i++) {
            uint8_t ch = value >> ((size - i - 1) * 8);
            if (s->bluetooth_attached) {
                smeg_hci_push_tx(&s->hci, ch, smeg_hci_capacity(s));
                smeg_hci_latch(s);
                if (s->psc_tx_enabled[1] && !timer_pending(s->hci_tx_timer))
                    timer_mod(s->hci_tx_timer,
                        qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 1000000);
                smeg_update_irq(s);
            }
            s->bluetooth_tx_count++;
            if (s->bluetooth_tx_prefix_len < sizeof(s->bluetooth_tx_prefix)) {
                s->bluetooth_tx_prefix[s->bluetooth_tx_prefix_len++] = ch;
            }
        }
    }
    if (off >= 0x11900 && off < 0x11a00 &&
        ((off & 0xff) == 0xbc || ((off & 0xff) == 0x0c && size == 1))) {
        for (unsigned i = 0; i < size; i++) {
            smeg_uart_tx_write(s, value >> ((size - i - 1) * 8));
        }
    }
}

static const MemoryRegionOps smeg_mmio_ops = {
    .read = smeg_mmio_read,
    .write = smeg_mmio_write,
    .endianness = DEVICE_BIG_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 8,
               .unaligned = true },
    .impl = { .min_access_size = 1, .max_access_size = 8,
              .unaligned = true },
};

static void smeg_reset(void *opaque)
{
    SmegMachineState *s = opaque;
    CPUPPCState *env = &s->cpu->env;
    qemu_bh_cancel(s->diu_present_bh);
    s->diu_fast_valid = false;
    cpu_reset(CPU(s->cpu));
    /* _sysInit initializes the real stack, SDA registers and BSS. */
    env->nip = KERNEL_ENTRY;
    env->gpr[1] = KERNEL_BASE - 16;
    env->gpr[3] = 0; /* Experimental VxWorks cold startType. */
    env->spr[SMEG_SPR_IMMR] = IMMR_BASE;
    /* NXP e300coreRM Table 2-3: MPC5121e e300c4, as distinct from
     * the generic QEMU e300c4 PVR 0x00860010. */
    env->spr[SPR_PVR] = 0x80860010;
    memset(s->regs, 0, sizeof(s->regs));
    smeg_reg_put(s, 0xc0, 0x20000000, 4); /* NXP MBXBAR reset value. */
    /* Explicit direct-kernel boot fixture: little-endian MBX core behind
     * the CPU bus byte swap normally configured before graphics startup. */
    smeg_reg_put(s, 0x104, 0x400, 4);
    smeg_reg_put(s, 0x2140, 0x8000f800, 4);
    smeg_reg_put(s, 0x2148, 0x3f, 4);
    memset(s->mbx_regs, 0, sizeof(s->mbx_regs));
    s->mbx_pb_initialized = false;
    s->mbx_pb_free_count = 0;
    memset(s->mbx_pb_free, 0, sizeof(s->mbx_pb_free));
    /* Native DevResetMBX accepts core class1, revision1 or2. This is the
     * explicit virtual class1/revision1.0 profile; lower revision bits and
     * zero feature word are assumptions, not physical-unit measurements. */
    s->mbx_regs[0xf00 / 4] = 0x01010000;
    s->diu_status = 0;
    timer_mod(s->diu_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 16666667);
    /* PSC clock callback divides by SCFR1 bits23..25. */
    smeg_reg_put(s, 0xf0c, 1U << 23, 4);
    s->dma_pending = 0;
    s->nfc_irq_level = false;
    s->usb_irq_level = false;
    s->nfc.bytes[0x1e1c] = s->nfc.bytes[0x1e1d] = 0;
    memset(s->psc_tx_enabled, 0, sizeof(s->psc_tx_enabled));
    memset(s->psc_rx_enabled, 0, sizeof(s->psc_rx_enabled));
    s->rx_head = s->rx_count = 0;
    s->bluetooth_tx_count = s->bluetooth_tx_prefix_len = 0;
    memset(&s->hci, 0, sizeof(s->hci));
    timer_del(s->hci_tx_timer);
    timer_del(s->uart_tx_timer);
    s->uart_tx_deadline_ns = 0;
    s->uart_tx_head = s->uart_tx_count = s->uart_tx_isr = 0;
    s->sdhc_clock_running = false;
    timer_del(s->touch_timer);
    s->touch_down = false;
    s->touch_x = s->touch_y = 0;
    s->spi_tx_count = 0;
    s->spi_rx_head = s->spi_rx_count = 0;
    s->spi_reply_valid = s->dma_servicing = false;
    s->dma_requests = 0;
    memset(s->dma_reported, 0, sizeof(s->dma_reported));
    {
        uint8_t bench_identity[4] = {5, 3, 9, 1};
        /* The secondary MCU is not reset by a PPC reboot. Preserve actual
         * virtual configuration writes independently of transport state.
         * A new QEMU process starts from its explicit optional fixtures. */
        uint8_t upg_config[16], system_config[16];
        bool have_upg_config = s->mcu.upg_config_enabled;
        bool have_system_config = s->mcu.system_config_enabled;
        memcpy(upg_config, s->mcu.upg_config, sizeof(upg_config));
        memcpy(system_config, s->mcu.system_config, sizeof(system_config));
        if (!have_upg_config) {
            have_upg_config = smeg_bench_config("SMEG_BENCH_MCU_UPG_CONFIG", upg_config);
        }
        if (!have_system_config) {
            have_system_config = smeg_bench_config("SMEG_BENCH_MCU_SYSTEM_CONFIG", system_config);
        }
        if (g_strcmp0(g_getenv("SMEG_BENCH_HW_PROFILE"), "int_e") == 0) {
            /* Row20 in the stock5.43 table reproduces all21 hardware flags
             * in the user's SPY capture; the default row21 remains INT_F. */
            bench_identity[1] = 2;
        }
        smeg_mcu_peer_init(&s->mcu, bench_identity);
        if (have_upg_config) {
            smeg_mcu_peer_set_upg_config(&s->mcu, upg_config);
        }
        if (have_system_config) {
            smeg_mcu_peer_set_system_config(&s->mcu, system_config);
        }
        const char *release_text = g_getenv("SMEG_BENCH_MCU_RELEASE");
        if (release_text && *release_text) {
            unsigned major, minor, patch;
            char trailing;
            if (strlen(release_text) != 8 ||
                sscanf(release_text, "%2x.%2x.%2x%c", &major, &minor,
                       &patch, &trailing) != 3) {
                error_report("SMEG_BENCH_MCU_RELEASE requires xx.xx.xx virtual firmware state");
                exit(EXIT_FAILURE);
            }
            const uint8_t release[3] = { major, minor, patch };
            smeg_mcu_peer_set_upg_sw_release(&s->mcu, release);
            warn_report("Virtual MCU software release %s is explicitly configured; not measured car data",
                        release_text);
        }
        s->mcu.bench_key_profile = s->bench_key_profile;
        /* Select the virtual MENU/SRC panel before native key-table caching,
         * including guest-requested resets. This does not change the board
         * identity, captured FMUX configuration, or application availability. */
        if (s->bench_key_profile &&
            g_strcmp0(g_getenv("SMEG_BENCH_KEY_VARIANT"), "a1") == 0) {
            s->mcu.key_variant = 0xa1;
        }
    }
    timer_del(s->bench_net_timer);
    memset(s->bench_net_next_ns, 0, sizeof(s->bench_net_next_ns));
    smeg_bench_alert_reset(&s->bench_alert);
    s->bench_esp_enabled = true;
    if (s->bench_net_valid & 0x40) {
        static const uint8_t neutral[8] = {0x7f,0xff,0,0,0,0,0,0};
        memcpy(s->bench_net_payload[6], neutral, sizeof(neutral));
    }
    if (g_strcmp0(g_getenv("SMEG_BENCH_ECO_OFF"), "1") == 0) {
        s->bench_net_payload[0][3] =
            (s->bench_net_payload[0][3] & 0x3f) | 0x80;
        s->bench_net_valid |= 1;
    }
    smeg_sync_bench_led(s);
    if (s->bench_net_valid) {
        timer_mod(s->bench_net_timer,
                  qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 100000000);
    }
    smeg_update_irq(s);
}

/* Explicit virtual-vehicle fixtures. These travel through the original /DevNet
 * MCU transport; no physical CAN interface is opened or written by this board. */
static const uint8_t smeg_bench_net_id[SMEG_BENCH_NET_COUNT] = {0x1a, 0x05, 0x0c, 0x15, 0x0f, 0x0e, 0x0b, 0x22, 0x02, 0x13, 0x1d};
static const uint8_t smeg_bench_net_len[SMEG_BENCH_NET_COUNT] = {5, 8, 6, 8, 7, 5, 8, 5, 8, 5, 1};
static const int64_t smeg_bench_net_period_ns[SMEG_BENCH_NET_COUNT] = {
    100000000, 100000000, 100000000, 50000000, 500000000, 500000000, 200000000, 100000000, 500000000, 1000000000, 500000000
};

static void smeg_bench_net_tick(void *opaque)
{
    SmegMachineState *s = opaque;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    int64_t next = INT64_MAX;
    if (s->bench_clock_live) {
        struct tm tm;
        qemu_get_timedate(&tm, 0);
        smeg_bench_date(s->bench_net_payload[9], &tm);
    }
    if (smeg_bench_alert_advance(&s->bench_alert, now,
                                s->bench_net_payload[6])) {
        s->bench_net_next_ns[6] = 0;
        qemu_log_mask(LOG_UNIMP, "SMEG virtual BSI alert pointer=%u (no physical CAN)\n",
                      (s->bench_net_payload[6][0] << 8) |
                       s->bench_net_payload[6][1]);
    }
    for (unsigned i = 0; i < SMEG_BENCH_NET_COUNT; i++) {
        if (s->bench_net_valid & (1U << i)) {
            if (s->bench_net_next_ns[i] <= now) {
                smeg_mcu_peer_net(&s->mcu, smeg_bench_net_id[i],
                                  s->bench_net_payload[i], smeg_bench_net_len[i]);
                s->bench_net_next_ns[i] = now + smeg_bench_net_period_ns[i];
            }
            next = MIN(next, s->bench_net_next_ns[i]);
        }
    }
    if (s->spi_reply_valid &&
        smeg_mcu_peer_net_pending(&s->mcu, s->spi_reply)) {
        smeg_spi_dma_requests(s);
    }
    if (s->bench_net_valid) {
        next = MIN(next, smeg_bench_alert_deadline(&s->bench_alert));
        timer_mod(s->bench_net_timer, next);
    }
}

static void smeg_bench_alert_queue(SmegMachineState *s, unsigned pointer)
{
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    if (smeg_bench_alert_request(&s->bench_alert, pointer, now)) {
        s->bench_net_valid |= 0x40;
        s->bench_net_next_ns[6] = 0;
        smeg_bench_net_tick(s);
    }
}

static void smeg_set_bench_alert(Object *obj, Visitor *v,
                                const char *name, void *opaque, Error **errp)
{
    SmegMachineState *s = SMEG_MACHINE(obj);
    g_autofree char *text = NULL;
    unsigned pointer;
    if (!visit_type_str(v, name, &text, errp)) {
        return;
    }
    if (!strcmp(text, "eco-on")) {
        pointer = 544;
    } else if (!strcmp(text, "eco-off")) {
        pointer = 545;
    } else {
        error_setg(errp, "bench-alert supports eco-on/eco-off; ordinary ESP uses bench-esp-enabled");
        return;
    }
    smeg_bench_alert_queue(s, pointer);
}

static bool smeg_get_bench_esp(Object *obj, Error **errp)
{
    return SMEG_MACHINE(obj)->bench_esp_enabled;
}

static void smeg_set_bench_esp(Object *obj, bool enabled, Error **errp)
{
    SmegMachineState *s = SMEG_MACHINE(obj);
    s->bench_esp_enabled = enabled;
    smeg_bench_alert_queue(s, enabled ? 313 : 314);
}

static void smeg_get_bluetooth_prefix(Object *obj, Visitor *v,
                                      const char *name, void *opaque, Error **errp)
{
    SmegMachineState *s = SMEG_MACHINE(obj);
    char hex[513];
    for (unsigned i = 0; i < s->bluetooth_tx_prefix_len; i++) {
        snprintf(hex + 2 * i, 3, "%02x", s->bluetooth_tx_prefix[i]);
    }
    hex[2 * s->bluetooth_tx_prefix_len] = 0;
    char *value = hex;
    visit_type_str(v, name, &value, errp);
}

static bool smeg_get_bench_clock(Object *obj, Error **errp)
{
    return SMEG_MACHINE(obj)->bench_clock_live;
}

static void smeg_set_bench_clock(Object *obj, bool enabled, Error **errp)
{
    SmegMachineState *s = SMEG_MACHINE(obj);
    s->bench_clock_live = enabled;
    s->bench_net_valid |= 1U << 9;
    s->bench_net_next_ns[9] = 0;
    smeg_bench_net_tick(s);
}

static void smeg_get_bench_temperature(Object *obj, Visitor *v,
                                      const char *name, void *opaque, Error **errp)
{
    uint64_t raw = SMEG_MACHINE(obj)->bench_net_payload[8][6];
    visit_type_uint64(v, name, &raw, errp);
}

static void smeg_set_bench_temperature(Object *obj, Visitor *v,
                                      const char *name, void *opaque, Error **errp)
{
    SmegMachineState *s = SMEG_MACHINE(obj);
    uint64_t raw;
    if (!visit_type_uint64(v, name, &raw, errp)) return;
    if (raw > 255 || !smeg_bench_temperature(s->bench_net_payload[8], raw)) {
        error_setg(errp, "temperature raw value must be0..250 or255 (unknown)");
        return;
    }
    s->bench_net_valid |= 1U << 8;
    s->bench_net_next_ns[8] = 0;
    smeg_bench_net_tick(s);
}

static void smeg_set_bench_can(Object *obj, Visitor *v,
                               const char *name, void *opaque, Error **errp)
{
    SmegMachineState *s = SMEG_MACHINE(obj);
    g_autofree char *text = NULL;
    uint8_t data[8];
    int slot = -1;
    if (!visit_type_str(v, name, &text, errp)) {
        return;
    }
    size_t n = strlen(text);
    if (n < 3 || text[2] != ':' || (n - 3) % 2 || n > 19) {
        error_setg(errp, "bench-can expects a verified local ID and hex payload, e.g. 1a:0000008000");
        return;
    }
    int hi = g_ascii_xdigit_value(text[0]);
    int lo = g_ascii_xdigit_value(text[1]);
    if (hi < 0 || lo < 0) {
        error_setg(errp, "invalid bench CAN local ID");
        return;
    }
    unsigned id = (hi << 4) | lo;
    for (unsigned i = 0; i < SMEG_BENCH_NET_COUNT; i++) {
        if (id == smeg_bench_net_id[i] && (n - 3) / 2 == smeg_bench_net_len[i]) {
            slot = i;
        }
    }
    if (slot < 0) {
        error_setg(errp, "bench CAN supports native local IDs 1a/05/0c/15/0f/0e/0b/22/02/13/1d with 5/8/6/8/7/5/8/5/8/5/1 bytes");
        return;
    }
    for (unsigned i = 0; i < smeg_bench_net_len[slot]; i++) {
        hi = g_ascii_xdigit_value(text[3 + i * 2]);
        lo = g_ascii_xdigit_value(text[4 + i * 2]);
        if (hi < 0 || lo < 0) {
            error_setg(errp, "invalid bench CAN payload hex");
            return;
        }
        data[i] = (hi << 4) | lo;
    }
    memcpy(s->bench_net_payload[slot], data, smeg_bench_net_len[slot]);
    if (slot == 9) {
        s->bench_clock_live = false;
    }
    if (slot == 6) {
        /* Explicit raw diagnostic input replaces any managed notification. */
        smeg_bench_alert_reset(&s->bench_alert);
    }
    s->bench_net_valid |= 1U << slot;
    s->bench_net_next_ns[slot] = 0;
    if (slot == 0 || slot == 1) {
        smeg_sync_bench_led(s);
    }
    qemu_log_mask(LOG_UNIMP, "SMEG simulated vehicle fixture %s (no physical CAN)\n", text);
    smeg_bench_net_tick(s);
}

static void smeg_set_frontpanel_event(Object *obj, Visitor *v,
                                     const char *name, void *opaque,
                                     Error **errp)
{
    SmegMachineState *s = SMEG_MACHINE(obj);
    uint64_t value = 0;
    if (!visit_type_uint64(v, name, &value, errp)) {
        return;
    }
    unsigned id = value >> 8;
    unsigned status = value & 0xff;
    if (value > 0x440a || id > 0x44 || status < 1 || status > 10) {
        error_setg(errp, "frontpanel event requires native ID00..44 and status01..0a");
        return;
    }
    if (!smeg_mcu_peer_key(&s->mcu, id, status)) {
        error_setg(errp, "frontpanel input queue is full");
        return;
    }
    qemu_log_mask(LOG_UNIMP, "SMEG frontpanel queued id=%02x status=%02x\n",
                  id, status);
    if (s->spi_reply_valid &&
        smeg_mcu_peer_key_pending(&s->mcu, s->spi_reply)) {
        smeg_spi_dma_requests(s);
    }
}

static bool smeg_get_key_profile(Object *obj, Error **errp)
{
    return SMEG_MACHINE(obj)->bench_key_profile;
}

static void smeg_set_key_profile(Object *obj, bool enabled, Error **errp)
{
    SmegMachineState *s = SMEG_MACHINE(obj);
    s->bench_key_profile = enabled;
    s->mcu.bench_key_profile = enabled;
}

static void smeg_get_key_variant(Object *obj, Visitor *v,
                                const char *name, void *opaque, Error **errp)
{
    uint64_t value = SMEG_MACHINE(obj)->mcu.key_variant;
    visit_type_uint64(v, name, &value, errp);
}

static void smeg_set_key_variant(Object *obj, Visitor *v,
                                const char *name, void *opaque, Error **errp)
{
    SmegMachineState *s = SMEG_MACHINE(obj);
    uint64_t value = 0;
    if (!visit_type_uint64(v, name, &value, errp)) return;
    if (value > 0xff || !smeg_mcu_peer_set_key_variant(&s->mcu, value)) {
        error_setg(errp, "key variant requires bench-key-profile and native00/a1");
        return;
    }
    if (s->spi_reply_valid &&
        smeg_mcu_peer_profile_pending(&s->mcu, s->spi_reply)) {
        smeg_spi_dma_requests(s);
    }
}

static void smeg_get_upgrade_gl_base(Object *obj, Visitor *v,
                                     const char *name, void *opaque, Error **errp)
{
    uint64_t value=smeg_soft_gles_get_upgrade_base();
    visit_type_uint64(v,name,&value,errp);
}

static void smeg_set_upgrade_gl_base(Object *obj, Visitor *v,
                                     const char *name, void *opaque, Error **errp)
{
    uint64_t value=0;
    if (!visit_type_uint64(v,name,&value,errp)) return;
    if (runstate_is_running()) {
        error_setg(errp,"Pause the guest before configuring its observed updater GL base");
        return;
    }
    if (value>UINT32_MAX || !smeg_soft_gles_set_upgrade_base((uint32_t)value))
        error_setg(errp,"Updater GL base requires an installed renderer and a RAM .text address");
}

static void smeg_init(MachineState *machine)
{
    SmegMachineState *s = SMEG_MACHINE(machine);
    MemoryRegion *sysmem = get_system_memory();
    BlockBackend *blk;
    int64_t length;

    s->trace_io = g_getenv("SMEG_TRACE_IO") != NULL;
    s->trace_uart = g_getenv("SMEG_TRACE_UART") != NULL;
    s->trace_spi = g_getenv("SMEG_TRACE_SPI") != NULL;
    s->trace_mcu = g_getenv("SMEG_TRACE_MCU") != NULL;
    s->trace_touch = g_getenv("SMEG_TRACE_TOUCH") != NULL;
    s->nfc.trace_io = s->trace_io;
    if (machine->ram_size < 32 * MiB || machine->ram_size > GiB) {
        error_report("SMEG experimental RAM must be between 32 MiB and 1 GiB");
        exit(EXIT_FAILURE);
    }
    if (!machine->kernel_filename) {
        error_report("SMEG requires -kernel <raw BSP vxWorks.bin>");
        exit(EXIT_FAILURE);
    }
    s->cpu = POWERPC_CPU(cpu_create(machine->cpu_type));
    s->external_irq = qdev_get_gpio_in(DEVICE(s->cpu), PPC6xx_INPUT_INT);
    /* QEMU e300 lacks MPC5121E's IMMR SPR. Register storage semantics only;
     * this does not remap the physical MMIO window on writes. */
    if (!s->cpu->env.spr_cb[SMEG_SPR_IMMR].name) {
        spr_register(&s->cpu->env, SMEG_SPR_IMMR, "SMEG_IMMR",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic, IMMR_BASE);
    }
    /* RCW advertises a 200-MHz bus; native timer resource reads 49,999,999 Hz.
     * Keep TB/DEC at bus/4 so the configured 500-Hz VxWorks clock is real. */
    cpu_ppc_tb_init(&s->cpu->env, 50000000);
    memory_region_add_subregion(sysmem, 0, machine->ram);
    memory_region_init_io(&s->immr, OBJECT(machine), &smeg_mmio_ops, s,
                          "smeg.unimplemented-immr", IMMR_SIZE);
    memory_region_add_subregion(sysmem, IMMR_BASE, &s->immr);
    s->usb_host_enabled = g_strcmp0(g_getenv("SMEG_USB_HOST"), "1") == 0;
    if (s->usb_host_enabled) {
        DeviceState *usb = qdev_new("smeg-usb-ehci");
        qdev_prop_set_bit(usb, "big-endian-mmio", true);
        qdev_prop_set_bit(usb, "big-endian-desc", true);
        qdev_prop_set_bit(usb, "fsl-port-speed", true);
        object_property_add_child(OBJECT(machine), "usb-host", OBJECT(usb));
        sysbus_realize_and_unref(SYS_BUS_DEVICE(usb), &error_fatal);
        /* Container holes fall back to the IMMR register storage, retaining
         * native USBMODE/SYSIF outside standard EHCI capability/op registers. */
        memory_region_add_subregion(&s->immr, 0x4000,
                                    sysbus_mmio_get_region(SYS_BUS_DEVICE(usb), 0));
        sysbus_connect_irq(SYS_BUS_DEVICE(usb), 0,
                            qemu_allocate_irq(smeg_usb_irq, s, 0));
    }
    if (blk_by_name("smeg_sd")) {
        DeviceState *ctrl = qdev_new(TYPE_SMEG_SDHC);
        DeviceState *card;
        object_property_add_child(OBJECT(machine), "sd-host", OBJECT(ctrl));
        sysbus_realize_and_unref(SYS_BUS_DEVICE(ctrl), &error_fatal);
        memory_region_add_subregion_overlap(sysmem, 0x80001500,
            sysbus_mmio_get_region(SYS_BUS_DEVICE(ctrl), 0), 1);
        sysbus_connect_irq(SYS_BUS_DEVICE(ctrl), 0,
                            qemu_allocate_irq(smeg_sdhc_irq, s, 0));
        sysbus_connect_irq(SYS_BUS_DEVICE(ctrl), 1,
                            qemu_allocate_irq(smeg_sdhc_dma_irq, s, 0));
        card = qdev_new("sd-card");
        qdev_prop_set_drive(card, "drive", blk_by_name("smeg_sd"));
        qdev_realize_and_unref(card, qdev_get_child_bus(ctrl, "sd-bus"),
                               &error_fatal);
    }
    qemu_chr_fe_init(&s->serial, serial_hd(0), &error_fatal);
    qemu_chr_fe_set_handlers(&s->serial, smeg_serial_can_receive,
                             smeg_serial_receive, NULL, NULL, s, NULL, true);
    Chardev *bt_chr = qemu_chr_find("smeg-bt");
    if (bt_chr) {
        qemu_chr_fe_init(&s->bluetooth, bt_chr, &error_fatal);
        s->bluetooth_attached = true;
        qemu_chr_fe_set_handlers(&s->bluetooth, smeg_hci_can_receive,
                                 smeg_hci_receive_bytes, NULL, NULL,
                                 s, NULL, true);
    }
    s->diu_console = graphic_console_init(NULL, 0, &smeg_diu_graphics_ops, s);
    qemu_console_resize(s->diu_console, 800, 480);
    s->diu_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, smeg_diu_vblank, s);
    s->diu_present_bh = qemu_bh_new(smeg_present_frame, s);
    if (g_strcmp0(g_getenv("SMEG_SOFT_GLES"), "1") == 0) {
        smeg_soft_gles_install(&s->cpu->env, smeg_software_framebuffer,
                               smeg_frame_ready, s);
    }
    s->hci_tx_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, smeg_hci_drain, s);
    s->uart_tx_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, smeg_uart_tx_drain, s);
    s->touch_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, smeg_touch_timer, s);
    s->bench_net_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, smeg_bench_net_tick, s);
    s->bench_ecu_enabled = g_strcmp0(g_getenv("SMEG_BENCH_ECU"), "1") == 0;
    s->bench_key_profile = g_strcmp0(g_getenv("SMEG_BENCH_KEY_PROFILE"), "1") == 0;
    if (g_strcmp0(g_getenv("SMEG_BENCH_ECO_OFF"), "1") == 0) {
        /* 0x3e1 D3bits7:6=2 is the original decoder's disabled status.
         * This is a simulated ECU status, not persistent vehicle coding. */
        s->bench_net_payload[0][3] = 0x80;
        s->bench_net_valid = 1;
    }
    if (g_strcmp0(g_getenv("SMEG_BENCH_VEHICLE"), "1") == 0) {
        static const uint8_t parking_standby[8] = {0xb4,0xb0,0x15,0xfc,0xfc,0xac,0xc2,0};
        static const uint8_t traction_normal[6] = {0,0,0,0,2,0};
        static const uint8_t stationary[8] = {0,0,0,0,0,0,0,0x80};
        static const uint8_t functions_available[7] = {0,4,0,0,0,0,0};
        /* Unsupported two-bit LED fields are invalid3, rather than claiming
         * active lane/side-monitoring hardware. CAFR's one-bit LED is off. */
        static const uint8_t drive_leds[5] = {0,0x30,3,0x60,0};
        /* BSI0f6 principal-service state: native DRIVE receives raw1 from
         * D0bits4:3. This is an explicit awake bench state, not measured
         * vehicle ignition or engine-running data. */
        /* Explicit simulated20C. D6 >250 marks the sensor unavailable in
         * native12a0eb4; this fixture is never a physical measurement. */
        static const uint8_t principal_service[8] = {8,0,0,0,0,0,120,0};
        memcpy(s->bench_net_payload[1], parking_standby, sizeof(parking_standby));
        memcpy(s->bench_net_payload[2], traction_normal, sizeof(traction_normal));
        memcpy(s->bench_net_payload[3], stationary, sizeof(stationary));
        memcpy(s->bench_net_payload[4], functions_available, sizeof(functions_available));
        memcpy(s->bench_net_payload[7], drive_leds, sizeof(drive_leds));
        memcpy(s->bench_net_payload[8], principal_service, sizeof(principal_service));
        /* MCU-local CAN_NET_STATUS, not an arbitration ID on physical CAN.
         * Native129bef4: D0bit4 economy mode;129bf1c: bit3 network healthy.
         * Preserve the native constructor's phase bits0x60; advertise only
         * this synthetic network's healthy state. No warning filtering. */
        s->bench_net_payload[10][0] = 0x68;
        s->bench_net_valid |= 0x79e;
        s->bench_clock_live = true;
        smeg_sync_bench_led(s);
    }
    if (g_strcmp0(g_getenv("SMEG_BENCH_BODY_CONFIG"), "1") == 0) {
        /* BSI_INF_CFG (0x361), translated by the MCU to NET0e. D0bit7
         * validates InfoMenu; bit5 advertises Welcome Lighting. The native
         * PERSO consumer also requires the existing Welcome_Lighting UP flag.
         * The isolated feature launcher opts in after native menu validation. */
        static const uint8_t body_config[5] = {0xa0,0,0,0,0};
        memcpy(s->bench_net_payload[5], body_config, sizeof(body_config));
        s->bench_net_valid |= 0x20;
    }
    s->touch_mouse = qemu_add_mouse_event_handler(smeg_touch_mouse, s, 1,
                                                  "SMEG MCU touchscreen");
    qemu_activate_mouse_event_handler(s->touch_mouse);
    memory_region_init_io(&s->mbx, OBJECT(machine), &smeg_mbx_ops, s,
                          "smeg.experimental-mbx", 16 * MiB);
    memory_region_add_subregion(sysmem, 0x20000000, &s->mbx);

    blk = blk_by_name("smegflash");
    if (blk) {
        length = blk_getlength(blk);
        if (length < 0 || length > FLASH_SIZE) {
            error_report("smegflash must be at most 256 MiB");
            exit(EXIT_FAILURE);
        }
        memory_region_init_ram(&s->flash, NULL,
                               "smeg.synthetic-flash", FLASH_SIZE,
                               &error_fatal);
        memset(memory_region_get_ram_ptr(&s->flash), 0xff, FLASH_SIZE);
        if (blk_pread(blk, 0, length,
                      memory_region_get_ram_ptr(&s->flash), 0) < 0) {
            error_report("Failed to read smegflash backend");
            exit(EXIT_FAILURE);
        }
        memory_region_set_readonly(&s->flash, true);
        memory_region_add_subregion(sysmem, FLASH_BASE, &s->flash);
    }
    memset(s->nfc.bytes, 0xff, 0x1400);
    s->nfc.page_size = 2048;
    s->nfc.spare_size = 64;
    s->nfc.pages_per_block = 64;
    s->nfc.status = 0xc0;
    memset(s->nfc.id, 0xff, sizeof(s->nfc.id));
    s->nfc.irq_change = smeg_nfc_irq_changed;
    s->nfc.irq_opaque = s;
    if (blk) {
        s->nfc.flash = memory_region_get_ram_ptr(&s->flash);
        s->nfc.flash_size = length;
    }
    s->nfc.nand = blk_by_name("smegnand");
    if (s->nfc.nand) {
        static const uint8_t virtual_samsung_id[6] = {
            0xec, 0xda, 0x10, 0x95, 0x44, 0x00
        };
        int64_t nand_length = blk_getlength(s->nfc.nand);
        /* Like QEMU's standard NAND device: an if=none backend has not
         * granted device write permission until this frontend claims it. */
        if (blk_set_perm(s->nfc.nand,
                         BLK_PERM_CONSISTENT_READ | BLK_PERM_WRITE,
                         BLK_PERM_ALL, &error_fatal) < 0) {
            exit(EXIT_FAILURE);
        }
        /* Explicit virtual Samsung x8 profiles; this is not an
         * identification of the physical head unit's installed NAND. */
        if (nand_length != (256 * MiB / 2048) * (2048 + 64) &&
            nand_length != (512 * MiB / 2048) * (2048 + 64)) {
            error_report("smegnand requires 256 or 512 MiB data, "
                         "2048+64-byte pages");
            exit(EXIT_FAILURE);
        }
        s->nfc.nand_size = nand_length;
        memcpy(s->nfc.id, virtual_samsung_id, sizeof(virtual_samsung_id));
        if (nand_length == (512 * MiB / 2048) * (2048 + 64)) {
            s->nfc.id[1] = 0xdc;
            s->nfc.id[4] = 0x54;
        }
    }
    memory_region_init_io(&s->nfc.iomem, OBJECT(machine), &smeg_nfc_ops,
                          &s->nfc, "smeg.experimental-nfc", 0x2000);
    memory_region_add_subregion(sysmem, 0x40000000, &s->nfc.iomem);
    if (load_image_targphys(machine->kernel_filename, KERNEL_BASE,
                            machine->ram_size - KERNEL_BASE) < 0) {
        error_report("Failed to load raw SMEG kernel");
        exit(EXIT_FAILURE);
    }
    object_property_add(OBJECT(machine), "frontpanel-event", "uint64",
                        NULL, smeg_set_frontpanel_event, NULL, NULL);
    object_property_add(OBJECT(machine), "updater-gl-base", "uint64",
                        smeg_get_upgrade_gl_base,smeg_set_upgrade_gl_base,NULL,NULL);
    object_property_add(OBJECT(machine), "bench-can", "string",
                        NULL, smeg_set_bench_can, NULL, NULL);
    object_property_add(OBJECT(machine), "bench-alert", "string",
                        NULL, smeg_set_bench_alert, NULL, NULL);
    object_property_add_uint64_ptr(OBJECT(machine), "bluetooth-uart-rx-count",
                                  &s->hci.received, OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(OBJECT(machine), "bluetooth-uart-sent-count",
                                  &s->hci.transmitted, OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(OBJECT(machine), "bluetooth-uart-overruns",
                                  &s->hci.overrun, OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(OBJECT(machine), "bluetooth-uart-tx-count",
                                  &s->bluetooth_tx_count, OBJ_PROP_FLAG_READ);
    object_property_add(OBJECT(machine), "bluetooth-uart-tx-prefix", "string",
                        smeg_get_bluetooth_prefix, NULL, NULL, NULL);
    object_property_add_bool(OBJECT(machine), "bench-clock-live",
                             smeg_get_bench_clock, smeg_set_bench_clock);
    object_property_add(OBJECT(machine), "bench-temperature-raw", "uint64",
                        smeg_get_bench_temperature, smeg_set_bench_temperature, NULL, NULL);
    object_property_add_bool(OBJECT(machine), "bench-esp-enabled",
                             smeg_get_bench_esp, smeg_set_bench_esp);
    object_property_add_bool(OBJECT(machine), "bench-key-profile",
                             smeg_get_key_profile, smeg_set_key_profile);
    object_property_add(OBJECT(machine), "frontpanel-key-variant", "uint64",
                        smeg_get_key_variant, smeg_set_key_variant, NULL, NULL);
    object_property_add_uint64_ptr(OBJECT(machine), "nfc-read-count",
                                  &s->nfc.reads, OBJ_PROP_FLAG_READ);
    qemu_register_reset(smeg_reset, s);
    warn_report("Experimental SMEG harness: direct _sysInit boot; partial "
                "eDMA/IPIC/PSC, other MMIO stubs; use -d unimp,guest_errors "
                "-D mmio.log. Timebase and linear flash window are assumptions.");
}

static void smeg_machine_class_init(ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);
    mc->desc = "Experimental SMEG+ MPC5121E direct-kernel bring-up";
    mc->init = smeg_init;
    mc->default_cpu_type = POWERPC_CPU_TYPE_NAME("e300c4");
    mc->default_ram_size = 512 * MiB;
    mc->default_ram_id = "smeg.ram";
    mc->max_cpus = 1;
    mc->default_cpus = 1;
}

static const TypeInfo smeg_machine_type = {
    .name = TYPE_SMEG_MACHINE,
    .parent = TYPE_MACHINE,
    .instance_size = sizeof(SmegMachineState),
    .class_init = smeg_machine_class_init,
};

static void smeg_register_types(void)
{
    type_register_static(&smeg_usb_type);
    type_register_static(&smeg_machine_type);
}
type_init(smeg_register_types)
