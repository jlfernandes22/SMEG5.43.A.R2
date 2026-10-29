#!/usr/bin/env python3
"""Add opt-in BE register/descriptor support to QEMU 9.2 EHCI.

MPC5121 SMEG HCF sets regBigEndian and descBigEndian. USB transfer data
remain byte streams. Existing machines retain little-endian defaults.
"""
import argparse
from pathlib import Path


def replace(s, old, new):
    if new in s:
        return s
    if s.count(old) != 1:
        raise RuntimeError(f'Expected one patch anchor: {old[:90]!r}')
    return s.replace(old, new, 1)


def patch(root):
    paths = {n: root / 'hw/usb' / n for n in
             ('hcd-ehci.c', 'hcd-ehci.h', 'hcd-ehci-sysbus.c')}
    texts = {n: p.read_text() for n, p in paths.items()}
    h = texts['hcd-ehci.h']
    h = replace(h, '    bool companion_enable;', '''    bool companion_enable;
    bool big_endian_mmio;
    bool big_endian_desc;''')
    h = replace(h, '    bool big_endian_desc;', '''    bool big_endian_desc;
    bool fsl_port_speed;''')
    s = texts['hcd-ehci-sysbus.c']
    s = replace(s, '    DEFINE_PROP_UINT32("maxframes", EHCISysBusState, ehci.maxframes, 128),', '''    DEFINE_PROP_UINT32("maxframes", EHCISysBusState, ehci.maxframes, 128),
    DEFINE_PROP_BOOL("big-endian-mmio", EHCISysBusState,
                     ehci.big_endian_mmio, false),
    DEFINE_PROP_BOOL("big-endian-desc", EHCISysBusState,
                     ehci.big_endian_desc, false),''')
    c = texts['hcd-ehci.c']
    s = replace(s, '    DEFINE_PROP_BOOL("companion-enable", EHCISysBusState, ehci.companion_enable,', '''    DEFINE_PROP_BOOL("fsl-port-speed", EHCISysBusState,
                     ehci.fsl_port_speed, false),
    DEFINE_PROP_BOOL("companion-enable", EHCISysBusState, ehci.companion_enable,''')
    c = replace(c, '    val = s->portsc[addr >> 2];', '''    val = s->portsc[addr >> 2];
    if (s->fsl_port_speed) {
        /* FSL embedded-TT PSPD[27:26], used by the native EHCD port-status
         * reader. Report the attached peripheral's real negotiated speed;
         * never invent a port enable, device, or successful transaction. */
        USBDevice *dev = s->ports[addr >> 2].dev;
        val &= ~0x0c000000U;
        if (dev && dev->attached && (val & PORTSC_CONNECT)) {
            val |= dev->speed == USB_SPEED_HIGH ? 0x08000000U :
                   dev->speed == USB_SPEED_LOW ? 0x04000000U : 0;
        }
    }''')
    c = replace(c, '        *buf = le32_to_cpu(*buf);', '''        *buf = ehci->big_endian_desc ? be32_to_cpu(*buf) :
                                      le32_to_cpu(*buf);''')
    c = replace(c, '        uint32_t tmp = cpu_to_le32(*buf);', '''        uint32_t tmp = ehci->big_endian_desc ? cpu_to_be32(*buf) :
                                               cpu_to_le32(*buf);''')
    c = replace(c, '    return s->caps[addr];', '''    /* Capability storage is LE; BE register byte lanes are reversed. */
    return s->caps[s->big_endian_mmio ? (addr ^ 3) : addr];''')
    anchor = 'static USBPortOps ehci_port_ops = {'
    be_ops = '''/* Opt-in BE register layout; callbacks still exchange host integers. */
static const MemoryRegionOps ehci_mmio_caps_be_ops = {
    .read = ehci_caps_read,
    .write = ehci_caps_write,
    .valid.min_access_size = 1,
    .valid.max_access_size = 4,
    .impl.min_access_size = 1,
    .impl.max_access_size = 1,
    .endianness = DEVICE_BIG_ENDIAN,
};

static const MemoryRegionOps ehci_mmio_opreg_be_ops = {
    .read = ehci_opreg_read,
    .write = ehci_opreg_write,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .endianness = DEVICE_BIG_ENDIAN,
};

static const MemoryRegionOps ehci_mmio_port_be_ops = {
    .read = ehci_port_read,
    .write = ehci_port_write,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .endianness = DEVICE_BIG_ENDIAN,
};

'''
    c = replace(c, anchor, be_ops + anchor)
    old_init = '''    memory_region_init_io(&s->mem_caps, OBJECT(dev), &ehci_mmio_caps_ops, s,
                          "capabilities", CAPA_SIZE);
    memory_region_init_io(&s->mem_opreg, OBJECT(dev), &ehci_mmio_opreg_ops, s,
                          "operational", s->portscbase);
    memory_region_init_io(&s->mem_ports, OBJECT(dev), &ehci_mmio_port_ops, s,
                          "ports", 4 * s->portnr);'''
    new_init = '''    /* Device properties are finalized at realize, after instance init. */
    memory_region_init_io(&s->mem_caps, OBJECT(dev),
                          s->big_endian_mmio ? &ehci_mmio_caps_be_ops :
                                               &ehci_mmio_caps_ops, s,
                          "capabilities", CAPA_SIZE);
    memory_region_init_io(&s->mem_opreg, OBJECT(dev),
                          s->big_endian_mmio ? &ehci_mmio_opreg_be_ops :
                                               &ehci_mmio_opreg_ops, s,
                          "operational", s->portscbase);
    memory_region_init_io(&s->mem_ports, OBJECT(dev),
                          s->big_endian_mmio ? &ehci_mmio_port_be_ops :
                                               &ehci_mmio_port_ops, s,
                          "ports", 4 * s->portnr);

'''
    if new_init not in c:
        if c.count(old_init) != 1:
            raise RuntimeError('Missing original EHCI child region initialization')
        c = c.replace(old_init, '', 1)
        c = replace(c, '    memory_region_add_subregion(&s->mem, s->capsbase, &s->mem_caps);',
                    new_init + '    memory_region_add_subregion(&s->mem, s->capsbase, &s->mem_caps);')
    outputs = {'hcd-ehci.c': c, 'hcd-ehci.h': h, 'hcd-ehci-sysbus.c': s}
    for n, value in outputs.items():
        if value != texts[n]:
            paths[n].write_text(value)
    print('EHCI optional big-endian-mmio / big-endian-desc ready')


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('qemu_root', type=Path)
    patch(ap.parse_args().qemu_root)
