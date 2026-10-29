#!/usr/bin/env python3
"""Create a regular virtual USB containing only the 137 untouched factory files.

This negative/control experiment diagnoses stock updater UI emulation. It never
accesses physical media, changes checksums, or modifies any source package.
"""
import argparse
import json
import os
from pathlib import Path
import struct
import subprocess
from build_stock_restore import ROOT, inventory, require, sha, verify_usb_tree


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    image = a.output.resolve()
    require(image.is_relative_to(ROOT/'artifacts/phase15') and not a.output.is_symlink()
            and not image.exists() and image.suffix == '.raw', 'New Phase15 artifact image required')
    package = ROOT/'artifacts/phase2/package/SMEG_PLUS_UPG'
    original = inventory(package)
    historic = {}
    for line in (ROOT/'artifacts/phase2/firmware-inventory.jsonl').read_text().splitlines():
        item = json.loads(line)
        prefix = 'artifacts/phase2/package/SMEG_PLUS_UPG/'
        if item['path'].startswith(prefix):
            historic[item['path'][len(prefix):]] = {'bytes':item['size'],'sha256':item['sha256']}
    require(original == historic and len(original) == 137, 'Factory source differs from original inventory')
    image.parent.mkdir(parents=True, exist_ok=True)
    size, first = 2*1024**3, 2048
    sectors = size//512-first
    mbr = bytearray(512)
    mbr[446:462] = struct.pack('<B3sB3sII', 0, b'\xfe\xff\xff', 12, b'\xfe\xff\xff', first, sectors)
    mbr[510:] = b'\x55\xaa'
    with image.open('xb') as f:
        f.truncate(size)
        f.write(mbr)
    subprocess.run(['mkfs.vfat','-F','32','-n','SMEGFACTORY','--offset',str(first),str(image),str(sectors//2)],
                   check=True,capture_output=True)
    subprocess.run(['mcopy','-s','-i',str(image)+'@@1048576',str(package),'::/'],
                   check=True,capture_output=True,env=dict(os.environ,MTOOLS_SKIP_CHECK='1'))
    verified = verify_usb_tree(image,package)
    require(inventory(package) == original, 'Source changed during virtual USB creation')
    report = {'scope':'Untouched factory control; emulator only','factory_source_unchanged':True,
              'factory_file_count':137,'no_added_databases_or_payloads':True,'physical_media_accessed':False,
              'image_sha256':sha(image),'factory_file_sha256':original,**verified}
    image.with_suffix('.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k != 'factory_file_sha256'}))


if __name__ == '__main__':
    main()
