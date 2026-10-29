#!/usr/bin/env python3
"""Build an emulator-only feature experiment from untouched factory databases.

Only identifiers present in this exact application's strings are used. Missing
MirrorLink/iPod-out keys are logged, not invented. No vehicle I/O is implemented.
"""
import argparse
import gzip
import hashlib
import json
import sqlite3
from pathlib import Path


def sha(b):
    return hashlib.sha256(b).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, default=Path(
        'artifacts/phase2/filesystems/NAV/system/Data_base/sqlite'))
    p.add_argument('--application', type=Path,
                   default=Path('artifacts/phase2/applications/NAV/app.bin'))
    p.add_argument('--output', type=Path, default=Path('artifacts/phase4/factory_db'))
    p.add_argument('--log', type=Path, default=Path('artifacts/phase4/flag_changes.log'))
    a = p.parse_args()
    if a.output.exists() or a.log.exists():
        p.error('output/log already exists; preserve previous experiments')
    from smeg_db_inf import encode_inf, verify_inf
    app = a.application.read_bytes()
    option_names = ['SW_OPTION_INTERNET', 'SW_OPTION_SMARTAPPS']
    for name in option_names:
        if name.encode() + b'\0' not in app:
            raise ValueError('identifier not verified in this application: ' + name)
    records = [{'operation': 'SCOPE', 'source': str(a.source),
                'application_sha256': sha(app), 'physical_car_io': False,
                'note': 'Factory emulator experiment; language/region not edited.'}]
    result = {}
    for filename in ['up_config.sqlite', 'config_options.sqlite']:
        original = (a.source / filename).read_bytes()
        decoded = gzip.decompress(original) if original[:2] == b'\x1f\x8b' else original
        if not decoded.startswith(b'SQLite format 3\0'):
            raise ValueError('not a SQLite database: ' + filename)
        c = sqlite3.connect(':memory:')
        c.deserialize(decoded)
        c.execute('PRAGMA trusted_schema=OFF')
        if c.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
            raise ValueError('factory integrity check failed')
        changes = []
        if filename == 'up_config.sqlite':
            before = c.execute('SELECT * FROM UP_Keys ORDER BY Section,Name,Idx').fetchall()
            for name, target in [('Wifi_active', 'WIFI'), ('Smartapps', 'APPS')]:
                row = c.execute('SELECT Type,IntValue FROM UP_Keys '
                                'WHERE Section=? AND Name=? AND Idx=?',
                                ('internet', name, 0)).fetchall()
                if len(row) != 1 or row[0][0] != 2:
                    raise ValueError('expected native boolean key missing: ' + name)
                sql = 'UPDATE UP_Keys SET IntValue=1 WHERE Section=? AND Name=? AND Idx=?'
                if c.execute(sql, ('internet', name, 0)).rowcount != 1:
                    raise ValueError('ambiguous key update')
                changes.append({'operation': 'UPDATE', 'database': filename,
                    'table': 'UP_Keys', 'column': 'IntValue', 'target': target,
                    'key': {'Section': 'internet', 'Name': name, 'Idx': 0},
                    'before': row[0][1], 'after': 1, 'sql': sql,
                    'parameters': ['internet', name, 0]})
            after = c.execute('SELECT * FROM UP_Keys ORDER BY Section,Name,Idx').fetchall()
            names = [r[1] for r in c.execute('PRAGMA table_info(UP_Keys)')]
            iv = names.index('IntValue')
            expected = [list(r) for r in before]
            for r in expected:
                if r[0] == 'internet' and r[1] in ('Wifi_active', 'Smartapps') and r[3] == 0:
                    r[iv] = 1
            if [tuple(r) for r in expected] != after:
                raise ValueError('unintended UP_Keys row/column change')
        else:
            columns = [r[1] for r in c.execute('PRAGMA table_info(sw_option)')]
            if columns != ['name', 'value']:
                raise ValueError('unexpected factory option schema')
            if c.execute('SELECT COUNT(*) FROM sw_option').fetchone()[0] != 0:
                raise ValueError('expected empty factory sw_option table')
            for name in option_names:
                sql = 'INSERT INTO sw_option(name,value) VALUES(?,?)'
                c.execute(sql, (name, 1))
                changes.append({'operation': 'INSERT', 'database': filename,
                    'table': 'sw_option', 'column': 'value', 'target': 'APPS',
                    'key': {'name': name}, 'before': None, 'after': 1,
                    'sql': sql, 'parameters': [name, 1],
                    'note': 'Factory table is empty; this inserts an existing application option identifier.'})
        c.commit()
        if c.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
            raise ValueError('modified SQLite integrity check failed')
        raw = c.serialize(); c.close()
        stored = gzip.compress(raw, mtime=0)
        inf = encode_inf(raw, stored, gzip_wrapped=True)
        verify_inf(raw, stored, inf)
        result[filename] = (raw, stored, inf)
        records.extend(changes)
        records.append({'operation': 'VALIDATE', 'database': filename,
            'factory_stored_sha256': sha(original), 'factory_raw_sha256': sha(decoded),
            'modified_raw_sha256': sha(raw), 'modified_stored_sha256': sha(stored),
            'sqlite_integrity_check': 'ok', 'stored_format': 'gzip',
            'native_inf': inf.decode('ascii')})
    for name in ['MIRROR_LINK', 'IPOD_OUT']:
        records.append({'operation': 'SKIP', 'target': name, 'rows_modified': 0,
                        'reason': 'No matching factory database key or application option identifier in SMEG5.43.A.R2.'})
    records.append({'operation': 'NOTE', 'text':
                    'UP_Keys has IntValue; sw_option has value. Neither table has BoolValue. No MirrorLink/CarPlay implementation is added.'})
    deploy_root = a.output / 'deploy'
    deploy = deploy_root / 'user_data/sqlite'
    deploy.mkdir(parents=True)
    decoded_dir = a.output / 'decoded'
    decoded_dir.mkdir()
    for filename, (raw, stored, inf) in result.items():
        (deploy / filename).write_bytes(stored)
        (deploy / (filename + '.inf')).write_bytes(inf)
        (decoded_dir / filename).write_bytes(raw)
    a.log.parent.mkdir(parents=True, exist_ok=True)
    a.log.write_text(''.join(json.dumps(r, sort_keys=True) + '\n' for r in records))
    print(json.dumps({'log': str(a.log), 'deployment_root': str(deploy_root),
                      'database_files': list(result), 'changes': 4,
                      'missing_targets': ['MIRROR_LINK', 'IPOD_OUT']}))


if __name__ == '__main__':
    main()
