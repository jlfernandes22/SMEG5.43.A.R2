#!/usr/bin/env python3
"""Create an empty, real FAT32 SD card image; deliberately contains no maps."""
import argparse
import json
from pathlib import Path
import shutil
import struct
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('refusing to overwrite existing media')
    if not shutil.which('mkfs.vfat'):
        parser.error('mkfs.vfat is required')
    size = 512 * 1024 * 1024
    first = 2048
    sectors = size // 512 - first
    args.output.parent.mkdir(parents=True, exist_ok=True)
    mbr = bytearray(512)
    # Standard FAT32 LBA partition. CHS saturated, geometry unused by SD.
    mbr[446:462] = struct.pack('<B3sB3sII', 0, b'\xfe\xff\xff',
                              0x0c, b'\xfe\xff\xff', first, sectors)
    mbr[510:512] = b'\x55\xaa'
    with args.output.open('xb') as f:
        f.truncate(size)
        f.write(mbr)
    try:
        subprocess.run(['mkfs.vfat', '-F', '32', '-n', 'SMEG_EMPTY',
                        '--offset', str(first), str(args.output),
                        str(sectors // 2)], check=True, capture_output=True)
        with args.output.open('rb') as f:
            f.seek(first * 512)
            boot = f.read(512)
        assert boot[510:] == b'\x55\xaa'
        assert boot[82:90] == b'FAT32   '
    except BaseException:
        args.output.unlink(missing_ok=True)
        raise
    report = {'image': str(args.output.resolve()), 'size': size,
              'partition_lba': first, 'partition_sectors': sectors,
              'filesystem': 'FAT32', 'maps_present': False,
              'files_added': [], 'purpose': 'native SD bring-up only'}
    args.output.with_suffix('.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
