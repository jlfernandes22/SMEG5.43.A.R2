#!/usr/bin/env python3
"""Validate Init response ID against the original native switch table."""
from pathlib import Path
import struct
kernel=Path('artifacts/phase2/package/SMEG_PLUS_UPG/BSP/SMEG_PLUS_512/vxWorks.bin').read_bytes()
base=0x72429c
handler=base+struct.unpack_from('>i',kernel,base-0x200000+3*4)[0]
assert handler==0x263190, 'LIBCOM response ID3 must select sequence comparison handler'
assert kernel[0x263190-0x200000:0x263198-0x200000]==bytes.fromhex('881e002d893f0003')
assert kernel[0x2631b4-0x200000:0x2631b8-0x200000]==bytes.fromhex('38800003'), 'Native handler signals Init event3'
print('Native LIBCOM ID3 sequence echo and event3 contract verified')
