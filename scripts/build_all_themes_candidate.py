#!/usr/bin/env python3
"""Build an artifact-only eight-theme candidate from the verified live backup.

No block devices, car connections or original backup modifications. This does
not certify physical compatibility or recovery. Native installation and visual
theme switching must be tested independently.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import struct
import subprocess

from build_franken_candidate import ROOT, ORIGINAL, update_controls, seal_contract
from build_stock_restore import verify_backup, inventory, verify_usb_tree, require
from ensure_smeg_fat_lfn import Fat32, lfn_record
from smeg_db_inf import encode_inf, verify_inf

PHASE = ROOT / 'artifacts/phase15'
BASE = ROOT / 'artifacts/phase13/candidate-v5/SMEG_PLUS_UPG'
THEMES = [(10, 'SQUARE', 101), (1, 'GRAPHIC', 102), (8, 'REDLINE', 103),
          (7, 'ESSENTIEL', 104), (11, 'WARMLIGHT', 201), (2, 'ELLIPTIC', 202),
          (3, 'CUBIC', 203), (4, 'REFLEX', 204)]


def sha(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def change_database(source, target, changes):
    stored = source.read_bytes()
    raw = gzip.decompress(stored)
    require(verify_inf(raw, stored, Path(str(source)+'.inf').read_bytes()), 'Original INF invalid')
    db = sqlite3.connect(':memory:')
    db.deserialize(raw)
    db.execute('PRAGMA trusted_schema=OFF')
    tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    def rows(table):
        return db.execute('SELECT * FROM "'+table.replace('"','""')+'"').fetchall()
    before = {t: rows(t) for t in tables}
    columns = [r[1] for r in db.execute('PRAGMA table_info(UP_Keys)')]
    expected = list(before['UP_Keys'])
    audit = []
    for section, name, column, value in changes:
        require(column in ('IntValue', 'StringValue'), 'Unexpected column')
        indices = [i for i, row in enumerate(expected)
                   if row[columns.index('Section')] == section and row[columns.index('Name')] == name
                   and row[columns.index('Idx')] == 0]
        require(len(indices) == 1, 'Non-unique target: '+section+'.'+name)
        i = indices[0]
        old = expected[i][columns.index(column)]
        if old == value:
            continue
        cursor = db.execute('UPDATE UP_Keys SET '+column+'=? WHERE Section=? AND Name=? AND Idx=0',
                            (value, section, name))
        require(cursor.rowcount == 1, 'Update affected wrong row count')
        updated = list(expected[i]); updated[columns.index(column)] = value; expected[i] = tuple(updated)
        audit.append({'database': source.name, 'table': 'UP_Keys', 'Section': section,
                      'Name': name, 'Idx': 0, 'column': column, 'old': old, 'new': value})
    db.commit()
    require(all(rows(t) == (expected if t == 'UP_Keys' else before[t]) for t in tables),
            'Unrequested database rows changed')
    require(db.execute('PRAGMA integrity_check').fetchall() == [('ok',)], 'SQLite integrity failure')
    raw = db.serialize(); db.close()
    packed = gzip.compress(raw, mtime=0)
    sidecar = encode_inf(raw, packed)
    require(verify_inf(raw, packed, sidecar), 'Generated INF invalid')
    target.write_bytes(packed); Path(str(target)+'.inf').write_bytes(sidecar)
    return audit


def usb_image(package, image):
    size = 2*1024**3; first = 2048; sectors = size//512-first
    mbr = bytearray(512)
    mbr[446:462] = struct.pack('<B3sB3sII', 0, b'\xfe\xff\xff', 12, b'\xfe\xff\xff', first, sectors)
    mbr[510:] = b'\x55\xaa'
    with image.open('xb') as f:
        f.truncate(size); f.write(mbr)
    subprocess.run(['mkfs.vfat', '-F', '32', '-n', 'SMEG_THEMES', '--offset', str(first),
                    str(image), str(sectors//2)], check=True, capture_output=True)
    subprocess.run(['mcopy', '-s', '-i', str(image)+'@@1048576', str(package), '::/'],
                   check=True, capture_output=True, env=dict(os.environ, MTOOLS_SKIP_CHECK='1'))
    with image.open('r+b') as f:
        volume = Fat32(f, size)
        parent, target, _ = volume.target()
        before = volume.payload_hashes(target['cluster'])
        if target['lfn'] != 'sqlite':
            require(not target['lfn_offsets'], 'Unexpected existing sqlite LFN')
            slots = list(volume.slots(parent))
            index = next(i for i, (off, _) in enumerate(slots) if off == target['offset'])
            require(index+2 < len(slots) and slots[index+1][1][0] in (0, 229), 'No LFN slot')
            raw = bytes.fromhex(target['raw_hex'])
            f.seek(target['offset']); f.write(lfn_record('sqlite', raw[:11]))
            f.seek(slots[index+1][0]); f.write(raw); f.flush(); os.fsync(f.fileno())
        _, target, _ = volume.target()
        require(target['lfn'] == 'sqlite' and before == volume.payload_hashes(target['cluster']),
                'LFN correction changed data')
    return {**verify_usb_tree(image, package), 'path': str(image), 'bytes': size,
            'sha256': sha(image), 'native_literal_sqlite_LFN_verified': True}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--assets', type=Path, default=PHASE/'theme-assets')
    p.add_argument('--image', type=Path)
    a = p.parse_args()
    out = a.output.resolve(); assets = a.assets.resolve()
    require(out.is_relative_to(PHASE) and out.name == 'SMEG_PLUS_UPG' and not out.exists(),
            'Only new Phase15 package permitted')
    require(assets.is_relative_to(PHASE) and (assets/'manifest.json').is_file(), 'Validated assets required')
    if a.image:
        require(a.image.resolve().is_relative_to(PHASE) and a.image.suffix == '.raw'
                and not a.image.exists() and not a.image.is_symlink(), 'Only new Phase15 image permitted')
    verify_backup()
    assets_manifest = json.loads((assets/'manifest.json').read_text())
    out.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(BASE, out, copy_function=shutil.copy2)
    asset_members = inventory(assets/'overlay')
    required_assets = {f'HARMONY/BigHarmony_{bank}/{name}{suffix}'
                       for bank in (4, 5)
                       for name in ('BIG_HARMONY.bin', 'BIG_SKIN_AUDIO.bin', 'BIG_SKIN_NAV.bin')
                       for suffix in ('', '.inf')}
    expected_assets = {r['path']: {'bytes': r['bytes'], 'sha256': r['SHA256']}
                       for r in assets_manifest['files']}
    require(set(asset_members) == required_assets and len(assets_manifest['files']) == 12
            and asset_members == expected_assets, 'Theme assets differ from validated manifest')
    for relative in asset_members:
        require(relative.startswith(('HARMONY/BigHarmony_4/', 'HARMONY/BigHarmony_5/')),
                'Unexpected theme asset path')
        shutil.copy2(assets/'overlay'/relative, out/relative)
    backup = ORIGINAL/'usb/SMEG_BACKUP'
    destination = out/'NAV/USER_DATA/user_data/sqlite'
    changes = [('internet', 'Web_active', 'IntValue', 1)]
    changes += [('display', 'Harm_'+str(i), 'IntValue', 1) for i, _, _ in THEMES]
    audit = change_database(backup/'up_config.sqlite', destination/'up_config.sqlite', changes)
    common = []
    for i, name, code in THEMES:
        common += [('supervisor', 'harmony'+str(i), 'StringValue', name),
                   ('supervisor', 'harm'+str(i)+'_offset_area', 'IntValue', code)]
    audit += change_database(backup/'up_common.sqlite', destination/'up_common.sqlite', common)
    unchanged = []
    for original in backup.glob('*.sqlite'):
        if original.name in ('up_common.sqlite', 'up_config.sqlite'):
            continue
        for source in (original, Path(str(original)+'.inf')):
            shutil.copy2(source, destination/source.name)
            require(sha(source) == sha(destination/source.name), 'Original database copy mismatch')
        unchanged.append(original.name)
    controls = update_controls(out)
    contract = seal_contract(out)
    report = {'artifact_only': True, 'physical_car_approved': False, 'physical_devices_accessed': False,
              'native_installation_test_completed': False, 'theme_visual_switch_test_completed': False,
              'base': str(BASE), 'themes': [{'hmi_id':i,'name':n,'physical_code':c} for i,n,c in THEMES],
              'original_Display_Color_and_default_skin_preserved': True,
              'database_changes': audit, 'all_other_rows_and_columns_preserved': True,
              'five_other_database_pairs_byte_exact_original': sorted(unchanged),
              'asset_members': asset_members, 'asset_manifest_sha256': sha(assets/'manifest.json'),
              'asset_scope': assets_manifest.get('scope', 'Eight original compiled theme resources; not new designs'),
              'control_changes': controls, 'contract': contract}
    if a.image:
        a.image.parent.mkdir(parents=True, exist_ok=True)
        report['virtual_USB'] = usb_image(out, a.image)
    verify_backup()
    (out.parent/'flag_changes.json').write_text(json.dumps(audit, indent=2)+'\n')
    (out.parent/'flag_changes.log').write_text('\n'.join(
        f"{r['database']} UP_Keys({r['Section']},{r['Name']},Idx=0).{r['column']}: {r['old']!r} -> {r['new']!r}"
        for r in audit)+'\nAll other rows and columns identical to original live backup.\n')
    (out.parent/'candidate-validation.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'candidate':str(out), 'theme_candidates':len(THEMES),
                      'changed_SQL_fields':len(audit), 'native_test_completed':False}))


if __name__ == '__main__':
    main()
