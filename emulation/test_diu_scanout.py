#!/usr/bin/env python3
"""Compile real DIU scanout plus its fast-path-disabled reference, no renderer copy."""
from pathlib import Path
import os
import subprocess
import tempfile
root = Path(__file__).resolve().parent
source = (root / 'smeg_diu.h').read_text().split('static void smeg_diu_vblank(', 1)[0]
start = source.index('static void smeg_diu_update(')
reference = source[start:].replace('smeg_diu_update(', 'smeg_diu_reference(', 1)
needle = 'if (smeg_diu_primary_fast(s, surface, width, height))'
assert reference.count(needle) == 1
reference = reference.replace(needle, 'if (false && smeg_diu_primary_fast(s, surface, width, height))')
with tempfile.TemporaryDirectory(prefix='smeg-diu-test-') as directory:
    temp = Path(directory)
    (temp / 'diu_production.inc').write_text(source + '\n' + reference)
    binary = temp / 'test_diu'
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-O2', '-Wall', '-Wextra',
                    '-Werror', '-I', str(temp), str(root / 'test_diu_scanout.c'),
                    '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
