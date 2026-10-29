#!/usr/bin/env python3
"""Export a stopped emulator's native VBF/FAT volume without changing NAND."""
import argparse
import mmap
import os
import subprocess
from pathlib import Path
from inject_volume import discover, mappings, bpb, extract

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--input', required=True, type=Path)
p.add_argument('--base-page', required=True, type=int)
p.add_argument('--output', required=True, type=Path)
a = p.parse_args()
if a.output.exists():
    p.error('output must not exist')
with a.input.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
    selected = [(k, h) for k, h in discover(mm).items()
                if min(x['page'] for x in h) == a.base_page]
    if len(selected) != 1:
        p.error('native volume not found or ambiguous')
    key, headers = selected[0]
    latest, _ = mappings(mm, headers, key[2])
    fs = bpb(mm, latest)
    if fs is None:
        p.error('native volume has no recognized FAT filesystem')
    data = extract(mm, latest, fs['sectors'])
a.output.mkdir(parents=True)
fat = a.output / 'volume.fat'
fat.write_bytes(data)
files = a.output / 'files'
files.mkdir()
subprocess.run(['mcopy', '-s', '-i', str(fat), '::/*', str(files)],
               env=dict(os.environ, MTOOLS_SKIP_CHECK='1'), check=True,
               capture_output=True)
print(files)
