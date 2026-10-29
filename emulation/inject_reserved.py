#!/usr/bin/env python3
"""Seed a verified raw reserved NAND area offline, preserving all FlashFX pages."""
import argparse
import hashlib
import json
from pathlib import Path

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--image',type=Path,default=Path('artifacts/phase3/nand.raw'))
p.add_argument('--source',type=Path,default=Path('artifacts/phase2/package/SMEG_PLUS_UPG/NAV/AppBin/f_BigQuick.bin'))
p.add_argument('--logical-offset',type=lambda s:int(s,0),default=0x014a0000)
a=p.parse_args()
data=a.source.read_bytes()
assert a.logical_offset+len(data)<=0x039c0000, 'Refusing to exceed verified area 1'
assert a.logical_offset>=0x014a0000, 'Refusing writes before verified application area'
with a.image.open('r+b') as image:
    position=0
    while position<len(data):
        logical=a.logical_offset+position
        page,column=divmod(logical,2048)
        amount=min(2048-column,len(data)-position)
        image.seek(page*2112+column)
        image.write(data[position:position+amount])
        position+=amount
with a.image.open('rb') as image:
    actual=bytearray()
    for position in range(0,len(data),2048):
        page,column=divmod(a.logical_offset+position,2048)
        image.seek(page*2112+column)
        actual.extend(image.read(min(2048,len(data)-position)))
assert actual==data
print(json.dumps({'source':str(a.source),'logical_offset':hex(a.logical_offset),
                  'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}))
