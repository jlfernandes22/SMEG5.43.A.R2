#!/usr/bin/env python3
"""Copy a stopped emulator NAND and erase only its application slot.

This models an unreadable application container, not an arbitrary physical
boot loop. It never opens a device. Other NAND bytes and the source stay intact.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[1]
START, END = 0x1100000, 0x2dc0000
PAGE, STRIDE = 2048, 2112


def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--stopped-prefix', required=True)
    a = p.parse_args()
    source, output = a.source.absolute(), a.output.absolute()
    if source.is_symlink() or not source.resolve().is_relative_to(ROOT/'artifacts'):
        p.error('Regular artifact source required')
    if not stat.S_ISREG(source.stat().st_mode) or source.stat().st_size != 553648128:
        p.error('Expected a regular 512MiB data + OOB emulator NAND')
    if output.is_symlink() or not output.resolve().is_relative_to(ROOT/'artifacts/phase14') or output.exists():
        p.error('New output under artifacts/phase14 required')
    if not a.stopped_prefix.startswith('/tmp/smeg-') or Path(a.stopped_prefix+'.qmp').exists():
        p.error('Source emulator must be stopped, with its private QMP socket absent')
    output.parent.mkdir(parents=True, exist_ok=True)
    before = digest(source)
    subprocess.run(['cp', '--reflink=auto', str(source), str(output)], check=True)
    first, last = START//PAGE*STRIDE, END//PAGE*STRIDE
    with output.open('r+b') as f:
        f.seek(first)
        left = last-first
        while left:
            take = min(left, 1024*1024)
            f.write(b'\xff'*take)
            left -= take
        f.flush()
        os.fsync(f.fileno())
    with source.open('rb') as s, output.open('rb') as t:
        position = 0
        while x := s.read(1024*1024):
            y = t.read(len(x))
            lo, hi = max(0, first-position), min(len(x), last-position)
            expected = x[:lo]+b'\xff'*(hi-lo)+x[hi:] if lo < hi else x
            if y != expected:
                raise RuntimeError('Unexpected change outside the application slot')
            position += len(x)
    if digest(source) != before:
        raise RuntimeError('Source changed')
    report = {'physical_devices_accessed': False, 'source': str(source.relative_to(ROOT)),
              'source_sha256': before, 'output': str(output.relative_to(ROOT)),
              'output_sha256': digest(output), 'erased_logical_range': [hex(START), hex(END)],
              'only_application_slot_erased': True, 'all_other_bytes_unchanged': True,
              'models': 'Unreadable application container with original BSP and other NAND state retained',
              'does_not_model': 'Arbitrary boot loop, broken U-Boot, dead MCU, wrong hardware geometry or power failure'}
    output.with_suffix('.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
