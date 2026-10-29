#!/usr/bin/env python3
"""Preserve the identified returned diagnostic stick through a read-only mount."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

from local_device_config import load_local_device_config

ROOT = Path(__file__).resolve().parents[1]
_LOCAL_DEVICE = load_local_device_config()
SERIAL = _LOCAL_DEVICE.get('usb_serial', '')
DEVICE = _LOCAL_DEVICE.get('usb_device', '')
MOUNT = Path(_LOCAL_DEVICE['usb_mount']) if _LOCAL_DEVICE.get('usb_mount') else None


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not (SERIAL and DEVICE.startswith('/dev/disk/by-id/') and MOUNT is not None and MOUNT.is_absolute()):
        parser.error('Configure USB identity and mount in .smeg-local.json or SMEG_USB_* first')
    output = args.output.resolve()
    assert output.is_relative_to(ROOT / 'artifacts/phase21') and not output.exists()
    state = json.loads(subprocess.check_output(
        ['lsblk', '-J', '-dn', '-o', 'NAME,SERIAL,MODEL,RM,TRAN', DEVICE], text=True,
    ))['blockdevices'][0]
    assert state['serial'] == SERIAL and state['rm'] and state['tran'] == 'usb'
    mounts = json.loads(subprocess.check_output(
        ['findmnt', '-J', '-S', DEVICE + '-part1', '-o', 'TARGET,OPTIONS'], text=True,
    ))['filesystems']
    assert len(mounts) == 1 and Path(mounts[0]['target']) == MOUNT
    assert 'ro' in mounts[0]['options'].split(',')
    paths = sorted(MOUNT.rglob('*'))
    assert paths and all(not path.is_symlink() for path in paths)
    (output / 'files').mkdir(parents=True)
    rows = []
    for source in paths:
        if not source.is_file():
            continue
        relative = source.relative_to(MOUNT)
        destination = output / 'files' / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        digest = sha(source)
        assert digest == sha(destination) and source.stat().st_size == destination.stat().st_size
        rows.append(dict(path=str(relative), bytes=destination.stat().st_size, sha256=digest))
    manifest = dict(
        created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        USB_serial=SERIAL, read_only_mount=True,
        all_files_copied_and_hash_verified=True, physical_car_accessed=False, files=rows,
    )
    (output / 'copy-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    for name in ['READCHECK.TXT', 'THEME_STATUS.TXT', 'UI_TRACE.TXT']:
        path = output / 'files' / name
        print(name)
        print(path.read_text()[:8000] if path.exists() else 'MISSING')
    print('BACKUP', output, 'FILES', len(rows))


if __name__ == '__main__':
    main()
