/* MPC5121 legacy SDHC frontend; NXP MPC5121ERM Rev4 chapter34.
 * Original guest protocol, QEMU SD card/backend. No fabricated map data.
 * FIFO is synchronous; separate DMA request output reflects card data readiness.
 * SDIO, detailed clock timing and migration are not implemented. */
#ifndef SMEG_SDHC_H
#define SMEG_SDHC_H
#include "hw/sysbus.h"
#include "hw/sd/sd.h"
#include "hw/irq.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/timer.h"
#define TYPE_SMEG_SDHC "smeg-mpc5121-sdhc"
OBJECT_DECLARE_SIMPLE_TYPE(SmegSdhc, SMEG_SDHC)
struct SmegSdhc {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    SDBus bus;
    qemu_irq irq, dma_irq;
    QEMUTimer *dma_timer;
    uint32_t regs[16], status, left, block_left;
    uint16_t response[8];
    unsigned resp_pos, resp_len;
    bool clock, write, pending;
};
static void smeg_sdhc_dma_timer(void *opaque)
{
    SmegSdhc *s = opaque;
    bool ready = s->left && !(s->status & 0x2000) &&
                 (s->write || sdbus_data_ready(&s->bus));
    qemu_set_irq(s->dma_irq, ready);
}
static void smeg_sdhc_irq_update(SmegSdhc *s)
{
    uint32_t m = s->regs[0x24 / 4], st = s->status;
    bool level = ((m & 4) && (st & 0x2000)) ||
        ((m & 2) && (st & 0x1000)) || ((m & 1) && (st & 0x800)) ||
        ((m & 0x10) && (st & 0x80)) || ((m & 8) && (st & 0x40)) ||
        ((m & 0x8000) && (st & 0x80000000)) ||
        ((m & 0x4000) && (st & 0x40000000));
    qemu_set_irq(s->irq, level);
    /* Command-response interrupt and data transfer are separate phases.
     * Defer bus-master entry outside this device's MMIO dispatch: a synchronous
     * FIFO callback would violate QEMU's MemoryRegion reentrancy guard. Allow
     * the command response to be acknowledged before scheduling the data phase;
     * instantaneous whole-block DMA before that ISR would incorrectly combine
     * READ_OP_DONE with its command-status W1C snapshot. No guest state is
     * injected: the later DMA still reads every byte from the real SD card. */
    if (s->dma_timer) {
        timer_mod(s->dma_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    }
}
static void smeg_sdhc_data_status(SmegSdhc *s)
{
    s->status &= ~(0x3c000000u | 0xc0);
    if (s->left) {
        if (s->write) {
            s->status |= 0x30000040; /* empty writable FIFO containers */
        } else if (sdbus_data_ready(&s->bus)) {
            s->status |= 0x0c000080; /* full readable FIFO containers */
        }
    }
    smeg_sdhc_irq_update(s);
}
static void smeg_sdhc_command(SmegSdhc *s)
{
    SDRequest request = { .cmd = s->regs[0x28 / 4] & 63,
                          .arg = s->regs[0x2c / 4] };
    uint8_t response[16] = {0};
    uint32_t control = s->regs[0xc / 4];
    int n;
    s->pending = false;
    s->resp_pos = s->resp_len = 0;
    s->left = 0;
    s->status &= ~(0x7e2fu);
    n = sdbus_do_command(&s->bus, &request, response);
    if ((control & 7) && n == 0) {
        s->status |= 2; /* actual card response timeout */
    } else if (n == 4) {
        /* SDHC includes command header and trailing CRC in short response.
         * BSP reconstructs response=(fifo0<<24)|(fifo1<<8)|(fifo2>>8).
         * QEMU SD core has checked framing; CRC byte is not guest-consumed. */
        s->response[0] = ((request.cmd & 63) << 8) | response[0];
        s->response[1] = (response[1] << 8) | response[2];
        s->response[2] = response[3] << 8;
        s->resp_len = 3;
    } else if (n == 16) {
        for (unsigned i = 0; i < 8; i++) {
            s->response[i] = (response[i * 2] << 8) | response[i * 2 + 1];
        }
        s->resp_len = 8;
    }
    s->status |= 0x2000;
    if ((control & 8) && !(s->status & 2)) {
        s->write = control & 0x10;
        s->block_left = s->regs[0x18 / 4] & 0xfff;
        s->left = s->block_left * (s->regs[0x1c / 4] & 0xffff);
    }
    if (getenv("SMEG_TRACE_SD")) {
        qemu_log_mask(LOG_GUEST_ERROR,
          "SMEG SD cmd=%u arg=%08x control=%04x response=%d bytes=%u status=%08x\n",
          request.cmd, request.arg, control, n, s->left, s->status);
    }
    smeg_sdhc_data_status(s);
}
static void smeg_sdhc_byte_done(SmegSdhc *s)
{
    if (!s->left) { return; }
    s->left--;
    if (--s->block_left == 0) {
        if (s->regs[0x1c / 4]) { s->regs[0x1c / 4]--; }
        s->block_left = s->regs[0x18 / 4] & 0xfff;
    }
    if (!s->left) { s->status |= s->write ? 0x1000 : 0x800; }
}
static uint64_t smeg_sdhc_read(void *opaque, hwaddr off, unsigned size)
{
    SmegSdhc *s = opaque;
    uint32_t value = 0;
    switch (off) {
    case 0: return 0;
    case 4: smeg_sdhc_data_status(s); return s->status | (s->clock ? 0x100 : 0);
    case 0x20: return 0x400;
    case 0x34:
        return s->resp_pos < s->resp_len ? s->response[s->resp_pos++] : 0;
    case 0x38:
        for (unsigned i = 0; i < 4 && s->left && !s->write; i++) {
            if (!sdbus_data_ready(&s->bus)) { break; }
            value |= (uint32_t)sdbus_read_byte(&s->bus) << (8 * i);
            smeg_sdhc_byte_done(s);
        }
        smeg_sdhc_data_status(s);
        return value;
    default: return off < sizeof(s->regs) ? s->regs[off / 4] : 0;
    }
}
static void smeg_sdhc_reset(DeviceState *dev)
{
    SmegSdhc *s = SMEG_SDHC(dev);
    memset(s->regs, 0, sizeof(s->regs));
    s->regs[8 / 4] = 8;
    s->regs[0x10 / 4] = 0x40;
    s->regs[0x14 / 4] = 0xffff;
    s->status = s->left = s->block_left = 0;
    s->resp_pos = s->resp_len = 0;
    s->clock = s->pending = false;
    qemu_set_irq(s->irq, 0);
    if (s->dma_timer) { timer_del(s->dma_timer); }
    qemu_set_irq(s->dma_irq, 0);
}
static void smeg_sdhc_write(void *opaque, hwaddr off, uint64_t value, unsigned size)
{
    SmegSdhc *s = opaque;
    switch (off) {
    case 0:
        if (value & 8) { smeg_sdhc_reset(DEVICE(s)); }
        if (value & 1) { s->clock = false; }
        if (value & 2) { s->clock = true; }
        if (s->clock && s->pending) { smeg_sdhc_command(s); }
        break;
    case 4:
        s->status &= ~(value & 0xc0007e2f);
        smeg_sdhc_data_status(s);
        break;
    case 0x38:
        for (unsigned i = 0; i < 4 && s->left && s->write; i++) {
            sdbus_write_byte(&s->bus, value >> (8 * i));
            smeg_sdhc_byte_done(s);
        }
        smeg_sdhc_data_status(s);
        break;
    case 0x20: case 0x34: break;
    default:
        if (off < sizeof(s->regs)) { s->regs[off / 4] = value; }
        if (off == 0xc && !(value & 0x8000)) {
            s->pending = true;
            if (s->clock) { smeg_sdhc_command(s); }
        }
        smeg_sdhc_irq_update(s);
    }
}
static const MemoryRegionOps smeg_sdhc_ops = {
    .read = smeg_sdhc_read, .write = smeg_sdhc_write,
    .endianness = DEVICE_BIG_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};
static void smeg_sdhc_instance_init(Object *obj)
{
    SmegSdhc *s = SMEG_SDHC(obj);
    memory_region_init_io(&s->iomem, obj, &smeg_sdhc_ops, s, TYPE_SMEG_SDHC, 0x100);
    sysbus_init_mmio(SYS_BUS_DEVICE(obj), &s->iomem);
    sysbus_init_irq(SYS_BUS_DEVICE(obj), &s->irq);
    sysbus_init_irq(SYS_BUS_DEVICE(obj), &s->dma_irq);
    qbus_init(&s->bus, sizeof(s->bus), TYPE_SD_BUS, DEVICE(obj), "sd-bus");
    s->dma_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, smeg_sdhc_dma_timer, s);
}
static void smeg_sdhc_class_init(ObjectClass *klass, void *data)
{
    device_class_set_legacy_reset(DEVICE_CLASS(klass), smeg_sdhc_reset);
}
static const TypeInfo smeg_sdhc_type = {
    .name = TYPE_SMEG_SDHC, .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(SmegSdhc),
    .instance_init = smeg_sdhc_instance_init,
    .class_init = smeg_sdhc_class_init,
};
static void smeg_sdhc_register_types(void) { type_register_static(&smeg_sdhc_type); }
type_init(smeg_sdhc_register_types)
#endif
