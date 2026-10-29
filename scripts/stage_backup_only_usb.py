#!/usr/bin/env python3
"""Stage the tested backup-only candidate on the explicitly configured FAT32 USB.

Never formats media, removes exports, stages the parameter writer, or accesses
the car. Refuses an existing FLYING/SMEG_BACKUP directory rather than overwriting.
"""
import argparse
import datetime
import hashlib
import json
import os
import subprocess
from pathlib import Path

from smeg_db_inf import crc16
from local_device_config import load_local_device_config

ROOT = Path(__file__).resolve().parents[1]
CANDIDATE = ROOT / 'artifacts/phase8/usb-maintenance/physical-backup-candidate'
EXPECTED = {'FLYING/readonly_backup.out', 'FLYING/readonly_backup.out.inf',
            'FLYING/doctor_smeg_plus_i.inf', 'READ_ME_BACKUP.txt'}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mount', type=Path, required=True)
    args = parser.parse_args()
    identity = load_local_device_config()
    require(identity.get('usb_serial') and identity.get('usb_model')
            and identity.get('usb_capacity_bytes'),
            'Configure an explicit USB identity in .smeg-local.json or SMEG_USB_* first')
    target = args.mount.resolve()
    disks = json.loads(subprocess.check_output([
        'lsblk', '--tree', '-J', '-b', '-o', 'PATH,MODEL,SERIAL,SIZE,LABEL,FSTYPE,MOUNTPOINTS']))
    matches = [d for d in disks['blockdevices']
               if d.get('serial') == identity['usb_serial']
               and d.get('model', '').strip() == identity['usb_model']
               and int(d.get('size', 0)) == identity['usb_capacity_bytes']]
    require(len(matches) == 1, 'Expected exactly one explicitly identified USB')
    partitions = [p for p in matches[0].get('children', [])
                  if p.get('label') == 'SMEG_EXPORT' and p.get('fstype') == 'vfat'
                  and int(p['size']) == 28 * 1024**3]
    require(len(partitions) == 1, 'Expected the existing 28 GiB FAT32 export partition')
    partition = partitions[0]
    require(str(target) in partition.get('mountpoints', []), 'Mount does not belong to USB')
    mounts = json.loads(subprocess.check_output([
        'findmnt', '-J', '--target', str(target), '-o', 'SOURCE,TARGET,FSTYPE,OPTIONS']))
    mount = mounts['filesystems'][0]
    require(mount['source'] == partition['path'] and mount['target'] == str(target)
            and mount['fstype'] == 'vfat' and 'rw' in mount['options'].split(','),
            'Expected the identified partition mounted writable at its root')
    for name in ('FLYING', 'SMEG_BACKUP', 'SMEG_PLUS_UPG'):
        require(not (target / name).exists(), 'Refusing existing ' + name)
    require(not (target / 'READ_ME_BACKUP.txt').exists(), 'Instructions already exist')
    source = CANDIDATE / 'files'
    require({str(p.relative_to(source)) for p in source.rglob('*') if p.is_file()} == EXPECTED,
            'Candidate must contain exactly the backup-only files')
    proof = json.loads((CANDIDATE / 'emulator-validation.json').read_text())
    require(proof['passed'] is True, 'Matching emulator test must pass first')
    manifest = json.loads((CANDIDATE / 'readonly-progress.json').read_text())
    for item in manifest['files']:
        file = source / item['path']
        require(digest(file) == item['sha256'], 'Candidate payload changed')
        if file.name.endswith('.inf'):
            data = file.read_bytes()
            require(int(data[:4], 16) == crc16(data[4:]), 'Invalid INF CRC')
    doctor = (source / 'FLYING/doctor_smeg_plus_i.inf').read_bytes()[4:]
    require(doctor == b'0000\r\nACTION:TemporaryBootRom\r\n'
            b'LOAD_AND_EXECUTE:/bd0/FLYING/readonly_backup.out\r\n',
            'Only the temporary RAM backup entry is permitted')
    stock = json.loads((ROOT / 'artifacts/live_car_backup/2026-10-27-stock-spy/'
                       'copy-manifest.json').read_text())
    for item in stock['files']:
        require(digest(target / item['path']) == item['sha256'], 'Original SPY export changed')
    (target / 'FLYING').mkdir()
    staged = []
    for name in sorted(EXPECTED):
        data = (source / name).read_bytes()
        with (target / name).open('xb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        require(digest(target / name) == hashlib.sha256(data).hexdigest(), 'USB readback mismatch')
        staged.append({'path': name, 'bytes': len(data), 'sha256': digest(target / name)})
    for item in stock['files']:
        require(digest(target / item['path']) == item['sha256'], 'SPY preservation check failed')
    os.sync()
    result = {'time_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'serial': matches[0]['serial'], 'partition': partition['path'],
              'formatted': False, 'backup_only': True, 'parameter_writer_staged': False,
              'original_spy_files_preserved': len(stock['files']), 'physical_car_accessed': False,
              'screen_progress_implemented': False, 'progress': 'SMEG_BACKUP/status.txt',
              'completion': 'SMEG_BACKUP/COMPLETE.txt or FAILED.txt', 'files': staged}
    (CANDIDATE / 'usb-stage-result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
