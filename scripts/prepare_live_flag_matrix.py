#!/usr/bin/env python3
"""Prepare isolated emulator flag cases from verified original car databases.

No device access, flash image writes, update packaging, or physical USB writes.
Only up_config.sqlite IntValue cells change; every other stored source file
is copied byte for byte. CRC sidecars provide integrity, not authentication.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import sqlite3

from smeg_db_inf import encode_inf, verify_inf

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / 'artifacts/live_car_backup/2026-10-27-native-usb'
SOURCE = SOURCE_ROOT / 'usb/SMEG_BACKUP'
DESTINATION = ROOT / 'artifacts/phase9/live-flag-matrix'
FLAGS = ('Web_active', 'Wifi_active', 'Smartapps')
CASES = {
    'baseline': (0, 0, 0),
    'A': (1, 1, 0),
    'B': (1, 0, 1),
    'C': (0, 1, 1),
    'D': (1, 1, 1),
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def connection(raw):
    conn = sqlite3.connect(':memory:')
    conn.deserialize(raw)
    assert conn.execute('PRAGMA integrity_check').fetchall() == [('ok',)]
    return conn


def cells(raw):
    conn = connection(raw)
    try:
        return {
            (row[0], row[1], row[3]): row
            for row in conn.execute('SELECT * FROM UP_Keys').fetchall()
        }
    finally:
        conn.close()


def row_changes(before, after):
    left, right = cells(before), cells(after)
    assert left.keys() == right.keys(), 'Unexpected row insertion/deletion'
    conn = connection(before)
    columns = [col[1] for col in conn.execute('PRAGMA table_info(UP_Keys)')]
    conn.close()
    changes = []
    for key in left:
        for col, old, new in zip(columns, left[key], right[key]):
            if old != new:
                assert col == 'IntValue' and key[0] == 'internet' and key[1] in FLAGS
                changes.append({
                    'table': 'UP_Keys',
                    'key': {'Section': key[0], 'Name': key[1], 'Idx': key[2]},
                    'column': col, 'before': old, 'after': new,
                })
    return changes


def prepare(output):
    output = output.resolve()
    assert output.is_relative_to(ROOT / 'artifacts/phase9'), 'Output must stay in phase9'
    assert not output.exists(), 'Output already exists; choose a fresh output directory'
    source_manifest = json.loads((SOURCE_ROOT / 'copy-manifest.json').read_text())
    expected = {item['path']: item['sha256'] for item in source_manifest['files']}
    originals = {}
    validations = []
    for source in sorted(SOURCE.glob('*.sqlite')):
        stored, inf = source.read_bytes(), Path(str(source) + '.inf').read_bytes()
        for name, data in ((source.name, stored), (source.name + '.inf', inf)):
            assert sha256(data) == expected['SMEG_BACKUP/' + name], name + ' source hash mismatch'
            originals[name] = data
        raw = gzip.decompress(stored)
        verify_inf(raw, stored, inf)
        conn = connection(raw)
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        conn.close()
        validations.append({'name': source.name, 'stored_sha256': sha256(stored),
                            'raw_sha256': sha256(raw), 'integrity': 'ok',
                            'native_inf_verified': True, 'tables': [row[0] for row in tables]})
    assert len(validations) == 7, 'Expected the seven original exported databases'
    raw_original = gzip.decompress(originals['up_config.sqlite'])
    conn = connection(raw_original)
    evidence = []
    for flag in FLAGS:
        rows = conn.execute(
            'SELECT Section,Name,Type,Idx,IntValue,StringValue,typeof(IntValue),typeof(StringValue) '
            'FROM UP_Keys WHERE Section=? AND Name=?', ('internet', flag)).fetchall()
        assert len(rows) == 1 and rows[0][2:5] == (2, 0, 0), rows
        assert rows[0][5:] == (None, 'integer', 'null'), rows
        evidence.append(dict(zip(('Section', 'Name', 'Type', 'Idx', 'IntValue', 'StringValue',
                                   'sqlite_IntValue_type', 'sqlite_StringValue_type'), rows[0])))
    conn.close()
    output.mkdir(parents=True)
    (output / 'source-verification.json').write_text(json.dumps(validations, indent=2) + '\n')
    (output / 'type-evidence.json').write_text(json.dumps({
        'flags': evidence, 'conclusion': 'All three original rows use Type=2 and integer IntValue; '
        'Smartapps is not a string setting. StringValue remains NULL.'}, indent=2) + '\n')
    results = {}
    for label, values in CASES.items():
        case = output / 'cases' / label
        deploy = case / 'deploy/user_data/sqlite'
        deploy.mkdir(parents=True)
        for name, data in originals.items():
            (deploy / name).write_bytes(data)
        sql = []
        raw_modified = raw_original
        if label != 'baseline':
            conn = connection(raw_original)
            for flag, value in zip(FLAGS, values):
                if not value:
                    continue
                statement = ('UPDATE UP_Keys SET IntValue=1 WHERE Section=\'internet\' '
                             f'AND Name=\'{flag}\' AND Idx=0 AND Type=2 AND IntValue=0;')
                assert conn.execute(statement).rowcount == 1
                sql.append(statement)
            conn.commit()
            raw_modified = conn.serialize()
            conn.close()
            stored = gzip.compress(raw_modified, compresslevel=9, mtime=0)
            inf = encode_inf(raw_modified, stored)
            verify_inf(raw_modified, stored, inf)
            (deploy / 'up_config.sqlite').write_bytes(stored)
            (deploy / 'up_config.sqlite.inf').write_bytes(inf)
        diff = row_changes(raw_original, raw_modified)
        assert len(diff) == sum(values)
        file_manifest = []
        for name, original in originals.items():
            data = (deploy / name).read_bytes()
            allowed = name in ('up_config.sqlite', 'up_config.sqlite.inf') and label != 'baseline'
            if not allowed:
                assert data == original, name + ' unexpectedly differs'
            file_manifest.append({'name': name, 'sha256': sha256(data),
                                  'source_sha256': sha256(original),
                                  'stored_bytes_unchanged': data == original})
        for source in sorted(deploy.glob('*.sqlite')):
            stored = source.read_bytes()
            raw = gzip.decompress(stored)
            conn = connection(raw)
            conn.close()
            verify_inf(raw, stored, Path(str(source) + '.inf').read_bytes())
        (case / 'changes.sql').write_text('\n'.join(sql) + ('\n' if sql else '-- Exact original baseline; no SQL changes.\n'))
        (case / 'flag_changes.log').write_text('\n'.join(json.dumps(item) for item in diff) + '\n')
        (case / 'row-diff.json').write_text(json.dumps(diff, indent=2) + '\n')
        result = {'case': label, 'flags': dict(zip(FLAGS, values)), 'deploy': str(deploy),
                  'modified_rows': len(diff), 'sql': sql, 'files': file_manifest,
                  'all_seven_sqlite_integrity': 'ok', 'all_seven_native_inf_verified': True}
        (case / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
        results[label] = result
    for name, original in originals.items():
        assert (SOURCE / name).read_bytes() == original, 'Source unexpectedly changed'
    summary = {'source': str(SOURCE), 'source_verified_against_export_manifest': True,
               'emulator_only': True, 'physical_car_accessed': False, 'physical_usb_accessed': False,
               'native_inf_is_not_signature': True, 'originals_unchanged': True,
               'cases': results}
    (output / 'preparation.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({'output': str(output), 'cases': {name: data['deploy'] for name, data in results.items()},
                      'all_seven_sqlite_integrity': 'ok', 'all_native_inf_verified': True}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=DESTINATION)
    prepare(parser.parse_args().output)
