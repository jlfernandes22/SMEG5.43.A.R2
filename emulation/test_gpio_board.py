#!/usr/bin/env python3
"""Test production GPIO input and native reset conditions without running QEMU."""
from pathlib import Path
import re
import subprocess
import tempfile

source = Path(__file__).with_name('mpc5121e_smeg.c').read_text()
inputs = source.split('} else if (off == 0x1108 && size == 4) {', 1)[1].split(
    '} else if (off == 0x2144', 1)[0]
reset = re.search(r'    if \(off == 0x1108 && size == 4 && !\(previous_gpio.*?\n    }',
                  source, re.S)
assert reset
code = r'''
#include <stdint.h>
#include <assert.h>
#define MiB (1024ULL * 1024)
#define LOG_UNIMP 0
#define SHUTDOWN_CAUSE_GUEST_RESET 1
#define qemu_log_mask(...) ((void)0)
typedef struct { struct { uint64_t nand_size; } nfc; uint32_t direction; } SmegMachineState;
static uint32_t smeg_reg_get(SmegMachineState*s,unsigned off,unsigned size) {
    assert(off==0x1100 && size==4); return s->direction;
}
static unsigned resets;
static void qemu_system_reset_request(int cause) { assert(cause==1); resets++; }
static uint32_t read_gpio(SmegMachineState*s,uint32_t value) {
'''+inputs+r'''
    return value;
}
static void write_gpio(SmegMachineState*s,unsigned off,unsigned size,uint32_t previous_gpio,uint32_t value) {
'''+reset[0]+r'''
}
int main(void) {
    SmegMachineState s={0};
    s.nfc.nand_size=(512*MiB/2048)*2112;
    assert(read_gpio(&s,0)==0x00100180); /* Boardindex1 + inactive overcurrent. */
    assert((read_gpio(&s,0x700)&0x700)==0x100); /* Inputs override latch. */
    s.nfc.nand_size=(256*MiB/2048)*2112;
    assert((read_gpio(&s,0x700)&0x700)==0); /* Boardindex0 for256MiB. */
    s.direction=0x700;
    assert((read_gpio(&s,0x600)&0x700)==0x600); /* Outputs retain latch. */
    s.direction=0x3ae82040; s.nfc.nand_size=(512*MiB/2048)*2112;
    assert((read_gpio(&s,0x105000c0)&0x10000700)==0x10000100);
    write_gpio(&s,0x1108,4,0,0x10000000); assert(resets==1);
    write_gpio(&s,0x1108,4,0x10000000,0x10000000); assert(resets==1);
    write_gpio(&s,0x1108,4,0x10000000,0); assert(resets==1);
    write_gpio(&s,0x1100,4,0,0x10000000); assert(resets==1);
    write_gpio(&s,0x1108,2,0,0x10000000); assert(resets==1);
    s.direction=0; write_gpio(&s,0x1108,4,0,0x10000000); assert(resets==1);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='smeg-gpio-') as d:
    p=Path(d)/'test.c'; p.write_text(code); binary=Path(d)/'test'
    subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror',str(p),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
print('Production GPIO passed:256/512 descriptor straps, input/output isolation, inactive overcurrent, output-only rising reset and wrong-width/address rejection')
