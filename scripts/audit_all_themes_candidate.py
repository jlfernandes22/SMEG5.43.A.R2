#!/usr/bin/env python3
"""Read-only Phase15 package/virtual-USB audit; never opens NAND or a VM."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import sqlite3
import stat
import struct
import zlib

from build_franken_candidate import ROOT, resolve, ctrl_crc16, has_ctrl_layout, has_trailer
from build_stock_restore import verify_backup, verify_usb_tree, inventory
from package_database_update import validate_contract
from smeg_db_inf import crc16, verify_inf
from audit_persistent_candidate import expected_database_source

BACKUP = ROOT / 'artifacts/live_car_backup/2026-10-27-native-usb/usb/SMEG_BACKUP'
PHASE = ROOT / 'artifacts/phase15'
THEMES = [(10, 'SQUARE', 101), (1, 'GRAPHIC', 102), (8, 'REDLINE', 103), (7, 'ESSENTIEL', 104),
          (11, 'WARMLIGHT', 201), (2, 'ELLIPTIC', 202), (3, 'CUBIC', 203), (4, 'REFLEX', 204)]


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_db(path):
    packed = path.read_bytes()
    raw = gzip.decompress(packed)
    require(verify_inf(raw, packed, Path(str(path) + '.inf').read_bytes()), 'Invalid SQLite INF')
    connection = sqlite3.connect(':memory:')
    connection.deserialize(raw)
    connection.execute('PRAGMA trusted_schema=OFF')
    require(connection.execute('PRAGMA integrity_check').fetchall() == [('ok',)], 'SQLite integrity failure')
    schema = connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name").fetchall()
    tables = [row[1] for row in schema if row[0] == 'table']
    contents = {}
    columns = {}
    for name in tables:
        quoted = '"' + name.replace('"', '""') + '"'
        contents[name] = connection.execute('SELECT * FROM ' + quoted).fetchall()
        columns[name] = [row[1] for row in connection.execute('PRAGMA table_info(' + quoted + ')')]
    connection.close()
    return schema, contents, columns


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--package', type=Path, required=True)
    p.add_argument('--assets', type=Path, required=True)
    p.add_argument('--usb', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    package, assets, usb, output = [x.resolve() for x in (a.package, a.assets, a.usb, a.output)]
    require(all(x.is_relative_to(PHASE) for x in (package, assets, usb, output)), 'Phase15 artifacts only')
    require(not output.exists(), 'Preserve existing audit output')
    require(not a.usb.is_symlink() and stat.S_ISREG(usb.stat().st_mode), 'Regular virtual image only')
    before_backup = verify_backup()
    before = inventory(package)
    usb_before = sha(usb)
    manifest = json.loads((assets / 'manifest.json').read_text())
    expected_assets = {r['path']: {'bytes': r['bytes'], 'sha256': r['SHA256']} for r in manifest['files']}
    require(len(expected_assets) == len(manifest['files']) == 12, 'Exactly12 distinct asset members required')
    require(inventory(assets / 'overlay') == expected_assets, 'Asset files do not match final Gamma manifest')
    for name, expected in expected_assets.items():
        require(before[name] == expected, 'Candidate assets differ from final manifest: ' + name)
    expected_changes = {}
    for ID, name, code in THEMES:
        expected_changes['up_config.sqlite', 'display', 'Harm_' + str(ID), 0, 'IntValue'] = 1
        expected_changes['up_common.sqlite', 'supervisor', 'harmony' + str(ID), 0, 'StringValue'] = name
        expected_changes['up_common.sqlite', 'supervisor', 'harm' + str(ID) + '_offset_area', 0, 'IntValue'] = code
    expected_changes['up_config.sqlite', 'internet', 'Web_active', 0, 'IntValue'] = 1
    differences = []
    db_records = []
    destination = package / 'NAV/USER_DATA/user_data/sqlite'
    for original in sorted(BACKUP.glob('*.sqlite')):
        target = destination / original.name
        orig_schema, orig_rows, orig_columns = read_db(original)
        target_schema, target_rows, target_columns = read_db(target)
        require(orig_schema == target_schema and orig_columns == target_columns, 'Database schema changed')
        own_diffs = []
        for table, old in orig_rows.items():
            new = target_rows[table]
            require(len(old) == len(new), 'Rows inserted or deleted in ' + original.name)
            for row_index, (left, right) in enumerate(zip(old, new)):
                for index, (old_value, new_value) in enumerate(zip(left, right)):
                    if old_value == new_value:
                        continue
                    require(table == 'UP_Keys', 'Unexpected modified SQL table')
                    columns = orig_columns[table]
                    section, name, idx = [left[columns.index(c)] for c in ('Section', 'Name', 'Idx')]
                    column = columns[index]
                    key = original.name, section, name, idx, column
                    require(key in expected_changes and expected_changes[key] == new_value, 'Unrequested SQL modification')
                    own_diffs.append({'database': original.name, 'table': table, 'Section': section,
                                      'Name': name, 'Idx': idx, 'column': column,
                                      'old': old_value, 'new': new_value})
        if original.name not in ('up_config.sqlite', 'up_common.sqlite'):
            require(target.read_bytes() == original.read_bytes() and
                    Path(str(target) + '.inf').read_bytes() == Path(str(original) + '.inf').read_bytes(),
                    'One of five other database pairs is not byte-exact original')
        expected_source = expected_database_source(package, original)
        require(expected_source == (target if original.name in ('up_config.sqlite', 'up_common.sqlite') else original),
                'Stopped-state auditor source selection mismatch')
        db_records.append({'name': original.name, 'changes': len(own_diffs), 'INF_valid': True,
                           'integrity': 'ok', 'expected_source_for_stopped_auditor': str(expected_source.relative_to(ROOT))})
        differences.extend(own_diffs)
    require(len(differences) == 20, 'Expected exact20 changed SQL fields')
    # Verify every proposed value, including those already set in the car DB.
    for db_name in ('up_config.sqlite', 'up_common.sqlite'):
        _, tables, columns = read_db(destination / db_name)
        cols = columns['UP_Keys']
        for key, value in expected_changes.items():
            if key[0] != db_name:
                continue
            _, section, name, idx, column = key
            matches = [r for r in tables['UP_Keys'] if r[cols.index('Section')] == section and
                       r[cols.index('Name')] == name and r[cols.index('Idx')] == idx]
            require(len(matches) == 1 and matches[0][cols.index(column)] == value, 'Requested SQL value missing')
    controls = []
    for path in sorted(package.rglob('*ctrl.bin')):
        data = path.read_bytes()
        require(has_ctrl_layout(data) and has_trailer(data), 'Control layout/trailer invalid')
        checked = 0
        unresolved = []
        for i in range(struct.unpack_from('>I', data, 44)[0]):
            record = data[48 + 264 * i:48 + 264 * (i + 1)]
            name = record[:256].split(b'\0')[0].decode()
            target = resolve(package, name)
            if target is None:
                unresolved.append(name)
                continue
            kind, expected = struct.unpack_from('>II', record, 256)
            content = target.read_bytes()
            actual = len(content) if kind == 1 else zlib.crc32(content) if kind == 2 else ctrl_crc16(content) if kind == 3 else None
            require(actual == expected, 'Native control mismatch: ' + name)
            checked += 1
        controls.append({'path': str(path.relative_to(package)), 'resolved_entries_checked': checked,
                         'unresolved_embedded_tar_members': unresolved, 'trailing_crc32_valid': True})
    inf_records = []
    for path in sorted(package.rglob('*.inf')):
        target = Path(str(path)[:-4])
        if not target.is_file() or target.suffix == '.sqlite':
            continue
        sidecar = path.read_bytes()
        if len(sidecar) < 8:
            continue
        try:
            expected_meta, expected_content = int(sidecar[:4], 16), int(sidecar[4:8], 16)
        except ValueError:
            continue  # Non-sidecar .inf files are control metadata, not CRC pairs.
        require(crc16(sidecar[4:]) == expected_meta and crc16(target.read_bytes()) == expected_content,
                'Native INF mismatch: ' + str(path.relative_to(package)))
        inf_records.append(str(path.relative_to(package)))
    contract = validate_contract(package)
    usb_readback = verify_usb_tree(usb, package)
    require(sha(usb) == usb_before and inventory(package) == before, 'Audit sources changed')
    require(verify_backup() == before_backup, 'Original backup manifest changed')
    report = {'read_only_independent_audit': True, 'VM_or_NAND_access': False, 'physical_device_access': False,
              'package': str(package.relative_to(ROOT)), 'asset_manifest': str((assets / 'manifest.json').relative_to(ROOT)),
              'asset_manifest_sha256': sha(assets / 'manifest.json'), 'all12_asset_files_match_manifest': True,
              'database_records': db_records, 'exact_SQL_change_count': len(differences), 'SQL_changes': differences,
              'all_other_SQL_rows_columns_and_schema_preserved': True,
              'Display_Color10_and_harmN_number_all0_preserved': True,
              'controls': controls, 'native_nonSQLite_INF_pairs_verified': inf_records, 'contract': contract,
              'virtual_USB_readback': usb_readback, 'virtual_USB_sha256': usb_before,
              'all_package_file_sha256': before, 'audit_sources_and_original_backups_unchanged': True,
              'stored_auditor_Phase15_and_up_common_support_checked': True,
              'native_installation_or_theme_compatibility_proved_by_this_audit': False}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'audit': str(output.relative_to(ROOT)), 'SQL_changes': len(differences),
                      'asset_members': 12, 'control_files': len(controls), 'INF_pairs': len(inf_records),
                      'contract_records': contract['records_checked'], 'USB_members': usb_readback['all_package_members_readback_verified']}))


if __name__ == '__main__':
    main()
