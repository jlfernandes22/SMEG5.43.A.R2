#!/usr/bin/env python3
"""Construct a synthetic NAND image; the original guest formats BBM/VBF/DOSFS.

NAND layout: each page contains page_size data bytes then oob_size spare bytes.
All unused bytes are erased (ff), including bad-block markers. This intentionally
has no fabricated FlashFX allocation records. The guest's original autoformat
policy creates those records through actual NAND erase/program operations.
"""
import argparse
import hashlib
import json
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--package', type=Path, default=Path('artifacts/phase2/package/SMEG_PLUS_UPG'))
p.add_argument('--variant', choices=['256', '512'], default='512')
p.add_argument('--output', type=Path, default=Path('artifacts/phase3/nand.raw'))
p.add_argument('--size-mib', type=int, default=512, help='NAND data capacity, excluding spare bytes')
p.add_argument('--layout', choices=['nand', 'logical'], default='nand')
p.add_argument('--page-size', type=int, default=2048)
p.add_argument('--oob-size', type=int, default=64)
p.add_argument('--pages-per-block', type=int, default=64)
p.add_argument('--erased-only', action='store_true', help='omit optional boot payload seeds')
p.add_argument('--application', choices=['NAV', 'AUDIO_BT', 'AUDIO_BT_256'], default='NAV')
a = p.parse_args()
if a.output.exists():
    raise SystemExit('Refusing to overwrite existing flash image')
if a.page_size != 2048 or a.oob_size != 64 or a.pages_per_block != 64:
    raise SystemExit('Current NFC model supports only 2048+64-byte pages, 64 pages/block')
if a.size_mib not in (256, 512, 1024):
    raise SystemExit('Supported data capacities: 256, 512 or 1024 MiB')
size = a.size_mib * 1024 * 1024
page_count = size // a.page_size
stride = a.page_size + a.oob_size if a.layout == 'nand' else a.page_size
physical_size = page_count * stride
bsp = a.package / 'BSP' / ('SMEG_PLUS_' + a.variant)
regions = [] if a.erased_only else [(bsp / 'dbsystem.bin', 0x180000),
    (bsp / 'vxWorks.bin', 0x420000 if a.variant == '256' else 0x720000)]
if not a.erased_only and a.variant == '512':
    # Verified WriteNANDBigQuick/ReadNand_area area 1 in this kernel.
    regions.append((a.package / a.application / 'AppBin/f_BigQuick.bin', 0x014a0000))
a.output.parent.mkdir(parents=True, exist_ok=True)
metadata = {'synthetic': True, 'layout': a.layout, 'data_bytes': size,
            'physical_bytes': physical_size, 'page_size': a.page_size,
            'oob_size': a.oob_size if a.layout == 'nand' else 0,
            'pages_per_block': a.pages_per_block, 'blocks': page_count // a.pages_per_block,
            'nand_id_assumption': {256:'ecda10954400',512:'ecdc10955400',1024:'ecd310955800'}[a.size_mib],
            'oob_initial_state':'all ff; no bad blocks; guest generates runtime metadata',
            'flashfx_initial_state':'unformatted; guest BBM/VBF/DOSFS autoformat',
            'regions': []}
def physical_offset(logical):
    page, offset = divmod(logical, a.page_size)
    return page * stride + offset
with a.output.open('xb') as image:
    block = b'\xff' * (stride * a.pages_per_block)
    for _ in range(page_count // a.pages_per_block):
        image.write(block)
    for source, offset in regions:
        data = source.read_bytes()
        if offset + len(data) > size:
            raise SystemExit('flash image too small')
        position = 0
        while position < len(data):
            logical = offset + position
            amount = min(a.page_size - logical % a.page_size, len(data) - position)
            image.seek(physical_offset(logical))
            image.write(data[position:position + amount])
            position += amount
        metadata['regions'].append({'source': str(source), 'logical_offset': offset,
                                    'bytes':len(data), 'sha256':hashlib.sha256(data).hexdigest()})
with a.output.open('rb') as image:
    for region in metadata['regions']:
        digest = hashlib.sha256()
        for position in range(0, region['bytes'], a.page_size):
            image.seek(physical_offset(region['logical_offset'] + position))
            digest.update(image.read(min(a.page_size, region['bytes'] - position)))
        assert digest.hexdigest() == region['sha256']
    image.seek(a.page_size)
    if a.layout == 'nand':
        assert image.read(a.oob_size) == b'\xff' * a.oob_size
assert a.output.stat().st_size == physical_size
a.output.with_suffix('.json').write_text(json.dumps(metadata, indent=2) + '\n')
print(json.dumps({'output':str(a.output), 'physical_bytes':physical_size, 'blocks':metadata['blocks']}))
