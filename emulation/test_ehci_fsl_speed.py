#!/usr/bin/env python3
"""Exercise the installed production EHCI PORTSC read function without a guest."""
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
source = (root / 'sources/qemu/hw/usb/hcd-ehci.c').read_text()
match = re.search(r'static uint64_t ehci_port_read\(.*?\n}\n', source, re.S)
if not match or 'fsl_port_speed' not in match[0]:
    raise SystemExit('install the EHCI patch before testing')
preamble = r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
typedef uint64_t hwaddr;
enum { USB_SPEED_LOW=0, USB_SPEED_FULL=1, USB_SPEED_HIGH=2 };
#define PORTSC_CONNECT 1U
#define trace_usb_ehci_portsc_read(...) ((void)0)
typedef struct { bool attached; int speed; } USBDevice;
typedef struct { USBDevice *dev; } USBPort;
typedef struct { uint32_t portsc[6]; USBPort ports[6]; bool fsl_port_speed; unsigned portscbase; } EHCIState;
'''
checks = r'''
int main(void) {
    EHCIState s={0}; USBDevice high={true,USB_SPEED_HIGH};
    s.portsc[0]=0x1005; s.portsc[1]=0x1001;
    s.ports[0].dev=&high;
    assert(ehci_port_read(&s,0,4)==0x1005); /* Existing machines unchanged. */
    s.fsl_port_speed=true;
    assert(ehci_port_read(&s,0,4)==0x08001005);
    assert(s.portsc[0]==0x1005); /* Synthesized RO bits do not mutate status. */
    high.speed=USB_SPEED_LOW;
    assert(ehci_port_read(&s,0,4)==0x04001005);
    high.speed=USB_SPEED_FULL;
    assert(ehci_port_read(&s,0,4)==0x1005);
    high.speed=USB_SPEED_HIGH; high.attached=false;
    assert(ehci_port_read(&s,0,4)==0x1005);
    high.attached=true; s.portsc[0]=0x1000;
    assert(ehci_port_read(&s,0,4)==0x1000); /* No phantom device. */
    assert(ehci_port_read(&s,4,4)==0x1001); /* Per-port device lookup. */
    s.ports[0].dev=0; s.portsc[0]=0x0c001001;
    assert(ehci_port_read(&s,0,4)==0x1001); /* Disconnected speed clears. */
    s.fsl_port_speed=false;
    assert(ehci_port_read(&s,0,4)==0x0c001001);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='smeg-ehci-test-') as d:
    src = Path(d) / 'test.c'; binary = Path(d) / 'test'
    src.write_text(preamble + match[0] + checks)
    subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror',
                    '-Wno-unused-parameter',str(src),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
print('Production EHCI speed read passed: opt-in isolation, high/full/low, per-port lookup, detach, no phantom connection or status mutation')
