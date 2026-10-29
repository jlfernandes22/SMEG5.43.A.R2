#!/usr/bin/env python3
"""Build a separate two-theme native Grip Control demo from stopped images."""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


def digest(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--input', type=Path,
                    default=Path('artifacts/phase4/runs/features/nand-before-layout-v2.raw'))
    ap.add_argument('--base', type=Path,
                    default=Path('artifacts/phase4/variants/stable_layout_v2/deploy'))
    ap.add_argument('--output', type=Path,
                    default=Path('artifacts/phase4/runs/asr_demo_seed'))
    a = ap.parse_args()
    if a.output.exists():
        ap.error('output exists; preserve previous demo seeds')
    a.output.mkdir(parents=True)
    plan = Path('artifacts/phase4/plans/asr_square_demo.json')
    subprocess.run([sys.executable, 'scripts/build_feature_variant.py',
                    '--plan', str(plan), '--base', str(a.base),
                    '--output', str(a.output / 'variant')], check=True)
    intermediate = a.output / 'nand-user.raw'
    subprocess.run([sys.executable, 'emulation/inject_volume.py',
                    '--input', str(a.input), '--output', str(intermediate),
                    '--source', str(a.output / 'variant/deploy'),
                    '--serial', '0x1d55ac5f',
                    '--report', str(a.output / 'user-injection.json')], check=True)
    system = a.output / 'system_data'
    system.mkdir()
    (system / 'Harmony.ini').write_bytes(b'HARMONY=401\0')
    nand = a.output / 'nand.raw'
    subprocess.run([sys.executable, 'emulation/inject_volume.py',
                    '--input', str(intermediate), '--output', str(nand),
                    '--source', str(system), '--serial', '0x119e2028',
                    '--report', str(a.output / 'system-injection.json')], check=True)
    manifest = {'scope': 'Separate original Grip Control UI demo; no vehicle I/O',
                'input': str(a.input), 'input_sha256': digest(a.input),
                'base': str(a.base), 'plan': str(plan),
                'plan_sha256': digest(plan), 'output': str(nand),
                'output_sha256': digest(nand),
                'allowed_native_themes': {'6': 'SQUARE401', '9': 'WARMLIGHT402'},
                'initial_native_theme': 'SQUARE401 / Display_Color6',
                'AsrPlus': 1, 'native_runtime_validation': 'pending'}
    (a.output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'demo_seed': str(nand), 'sha256': manifest['output_sha256']}))


if __name__ == '__main__':
    main()
