#!/usr/bin/env python3
"""Index sandbox evidence; log scans alone do not prove a usable feature."""
import argparse
import hashlib
import json
from pathlib import Path
import re


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, default=Path('artifacts/phase4'))
    a = p.parse_args()
    cases = []
    patterns = {
        'data_access': r'data (?:access|storage) exception',
        'instruction_access': r'instruction (?:access|storage) exception',
        'stack_overflow': r'stack overflow',
        'sqlite_corruption': r'database disk image is malformed|SQLITE_CORRUPT',
        'host_fatal': r'qemu: fatal|assertion .* failed|segmentation fault',
    }
    for case in sorted((a.root / 'runs').iterdir()):
        if not case.is_dir():
            continue
        logs = sorted(case.rglob('*.serial.log'))
        windows = sorted(case.rglob('*.window.log'))
        serial = '\n'.join(f.read_text(errors='replace') for f in logs)
        host = '\n'.join(f.read_text(errors='replace') for f in windows)
        cases.append({'case': case.name, 'serial_logs': [str(f) for f in logs],
                      'serial_bytes': sum(f.stat().st_size for f in logs),
                      'recorded_gl_swaps': len(re.findall(r'SMEG software GL swap\d+', host)),
                      'log_marker_counts': {name: len(re.findall(pattern, serial+'\n'+host, re.I))
                                            for name, pattern in patterns.items()},
                      'screenshots': [str(f) for f in sorted(case.glob('*.png'))],
                      'interpretation': 'Requires UI inspection; absence of these markers is not a full guest health test.'})
    evidence = a.root / 'feature-findings.json'
    findings = json.loads(evidence.read_text()) if evidence.exists() else {}
    originals = {
        'kernel': ('artifacts/phase2/package/SMEG_PLUS_UPG/BSP/SMEG_PLUS_512/vxWorks.bin',
                   'e07a4e61e3c80b31e0d9bd795d3b099cfcb9cab32520086a9a8d9bc2fa1135d6'),
        'main_application': ('artifacts/phase2/applications/NAV/app.bin',
                             'a14f1d60a6335b493a3230bccffadc70266e7e7289c2b3e98d3e3a8b9583505b'),
    }
    firmware = {}
    for name, (path, expected) in originals.items():
        actual = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        firmware[name] = {'sha256': actual, 'matches_verified_package': actual == expected}
    report = {'scope': 'Isolated QEMU; physical car disconnected; no physical I/O',
              'firmware': firmware, 'cases': cases, 'verified_findings': findings}
    (a.root / 'feature-matrix.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'cases': len(cases), 'output': str(a.root / 'feature-matrix.json')}))


if __name__ == '__main__':
    main()
