#!/usr/bin/env python3
"""Replace only the bundled offline HTML on a separate stopped QEMU NAND copy.

The existing Connect Apps route already loads this local file. No DNS spoofing,
manufacturer traffic, firmware instructions or physical storage are involved.
"""
import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', required=True, type=Path,
                   help='Stopped emulator NAND snapshot (never a physical device)')
    p.add_argument('--case', default='local_apps')
    a = p.parse_args()
    if not a.case or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789_-' for c in a.case):
        p.error('invalid case name')
    source = a.input.resolve()
    if not source.is_relative_to(ROOT / 'artifacts') or not source.is_file():
        p.error('input must be a regular emulator artifact inside this workspace')
    case = ROOT / 'artifacts/phase4/runs' / a.case
    if case.exists():
        p.error('case already exists; preserve prior tests')
    case.mkdir(parents=True)
    template = ROOT / 'emulation/local_apps/index.html'
    with tempfile.TemporaryDirectory(prefix='smeg-local-apps-') as tmp:
        payload = Path(tmp) / 'internet_default/portal'
        payload.mkdir(parents=True)
        shutil.copyfile(template, payload / 'index.html')
        subprocess.run([
            'python3', str(ROOT / 'emulation/inject_volume.py'),
            '--input', str(source), '--output', str(case / 'nand.raw'),
            '--base-page', '92992', '--source', tmp,
            '--report', str(case / 'injection.json'),
        ], cwd=ROOT, check=True)
    (case / 'local-apps.json').write_text(json.dumps({
        'scope': 'Isolated QEMU copy; no physical car access',
        'source': str(source), 'html': str(template),
        'html_sha256': hashlib.sha256(template.read_bytes()).hexdigest(),
        'replaced_file': '/SYSTEM/internet_default/portal/index.html',
        'database_changes': [], 'firmware_instruction_changes': False,
        'requires': 'Existing sandbox URL_PSA_portal points to original local file',
        'native_runtime_verified': False,
        'online_apps': False, 'native_vehicle_controls': False,
    }, indent=2) + '\n')
    print(json.dumps({'case': a.case, 'launch': 'bash emulation/launch_local_apps.sh'}))


if __name__ == '__main__':
    main()
