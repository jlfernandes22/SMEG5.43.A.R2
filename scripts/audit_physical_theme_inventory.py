#!/usr/bin/env python3
"""Validate copied physical diagnostic results offline; never open devices."""
import hashlib
import json
import re
import struct
from pathlib import Path

from audit_usb_single_key import read_db, difference

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'artifacts/phase19/theme-inventory'
RETURN = BASE / 'physical-return'


def require(value, message):
    if not value:
        raise ValueError(message)


def main():
    files = RETURN / 'usb'
    backup = files / 'SMEG_BACKUP'
    manifest = json.loads((RETURN / 'copy-manifest.json').read_text())
    for row in manifest['files']:
        path = files / row['path']
        require(path.is_relative_to(files) and not path.is_symlink(), 'Unsafe copied path')
        data = path.read_bytes()
        require(len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256'],
                'Copied evidence changed: ' + row['path'])
    metadata = json.loads((BASE / 'usb-probe/usb.json').read_text())
    for row in metadata['files']:
        require(hashlib.sha256((files / row['path']).read_bytes()).hexdigest() == row['sha256'],
                'Diagnostic payload changed on returned USB')
    log = (backup / 'theme-inventory.txt').read_text()
    require('VERIFIED_BSP_READERS count=3' in log and 'ABORT' not in log,
            'Native readers were not verified')
    matches = re.findall(r'^THEME bank=(\d+) entry=(\d+) name=(.*?) HMI_slot=(\d+) '
                         r'payload_page=(\d+) payload_bytes=(\d+) CRC32=([0-9a-f]{8})$',
                         log, re.M)
    end = re.search(r'FINISHED read-only theme inventory; readable_entries=(\d+)\n?$', log)
    require(end and len(matches) == int(end[1]), 'Incomplete inventory')
    themes = []
    for bank, entry, name, slot, page, size, crc in matches:
        prefix = f'theme-bank{int(bank):02d}'
        paths = [backup / (prefix + '-preheader.bin'), backup / (prefix + '-directory.bin'),
                 backup / (prefix + f'-entry{int(entry):02d}.bin')]
        pre, directory, raw = [p.read_bytes() for p in paths]
        require([len(pre), len(directory), len(raw)] == [168, 36, 216], 'Header sizes invalid')
        require(raw[:196].split(b'\0')[0].decode('ascii') == name, 'Theme name mismatch')
        require(struct.unpack_from('>IIII', raw, 200) ==
                (int(slot), int(page), int(size), int(crc, 16)), 'Header fields disagree with log')
        require(1 <= int(entry) <= struct.unpack_from('>I', directory, 32)[0] <= 9,
                'Directory count invalid')
        same = {p.name: p.read_bytes() == (BASE / 'observed-headers' / p.name).read_bytes()
                for p in paths if (BASE / 'observed-headers' / p.name).exists()}
        themes.append(dict(bank=int(bank), entry=int(entry), name=name, HMI_slot=int(slot),
                           payload_bytes=int(size), header_files_match_QEMU_stock=same,
                           full_theme_payload_exported=False))
    previous = ROOT / 'artifacts/phase18/warmlight-physical-return/usb/SMEG_BACKUP'
    original = ROOT / 'artifacts/live_car_backup/2026-10-27-native-usb/usb/SMEG_BACKUP'
    dbs = []
    rows_by_name = {}
    for path in sorted(backup.glob('*.sqlite')):
        sidecar = Path(str(path) + '.inf')
        current = read_db(path.read_bytes(), sidecar.read_bytes())
        rows_by_name[path.name] = current
        record = dict(name=path.name, SQLite_integrity='ok', native_INF_and_raw_CRC_valid=True)
        for label, older in [('since_pre_WARMLIGHT_export', previous), ('since_original_export', original)]:
            source = older / path.name
            before = read_db(source.read_bytes(), Path(str(source) + '.inf').read_bytes())
            record[label] = difference(before, current)
        dbs.append(record)
    require(len(dbs) == 7, 'Expected seven databases')
    config = rows_by_name['up_config.sqlite']['UP_Keys']['rows']
    common = rows_by_name['up_common.sqlite']['UP_Keys']['rows']
    flags = [{k: r[k] for k in ('Section', 'Name', 'Idx', 'IntValue', 'StringValue')}
             for r in config if r['Section'] == 'display' and r['Name'].startswith('Harm_')]
    names = [{k: r[k] for k in ('Section', 'Name', 'Idx', 'IntValue', 'StringValue')}
             for r in common if (r['Section'] == 'supervisor' and re.fullmatch('harmony[0-9]+', r['Name']))
             or (r['Section'] == 'display_configuration' and r['Name'] == 'Display_Color')]
    report = dict(scope='Offline validation of returned physical read-only export',
                  inventory_complete=True, database_copy_status=(backup / 'status.txt').read_text(),
                  readable_theme_count=len(themes), themes=themes, theme_flags=flags,
                  harmony_names_and_selection=names, databases=dbs,
                  settings_or_firmware_written_by_this_host_audit=False,
                  notes=['Exported headers do not verify full theme payload integrity.',
                         'Earlier exports are from different sessions; differences cannot establish '
                         'changes during this read-only diagnostic.',
                         'Banks returning -1 are unreadable/absent through this API; this is not '
                         'a forensic scan of every NAND byte.'])
    out = RETURN / 'validation.json'
    require(not out.exists(), 'Preserve existing validation history')
    out.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('inventory_complete', 'readable_theme_count',
                                           'themes', 'theme_flags', 'harmony_names_and_selection')}, indent=2))
    print('All seven databases passed SQLite integrity and native checksum validation.')
    for db in dbs:
        print(db['name'], 'changed tables since pre-WARMLIGHT export:',
              [r['table'] for r in db['since_pre_WARMLIGHT_export']])


if __name__ == '__main__':
    main()
