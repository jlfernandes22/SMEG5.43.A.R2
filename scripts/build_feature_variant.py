#!/usr/bin/env python3
"""Apply an explicit, logged feature plan to an emulator-only deployment tree.

UP_Keys rows must exist. New sw_option rows must name identifiers compiled into
the original application. No vehicle access, firmware patch, or schema changes.
"""
import argparse
import gzip
import hashlib
import json
import shutil
import sqlite3
from pathlib import Path
from smeg_db_inf import encode_inf, verify_inf


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--plan', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--base', type=Path, default=Path('artifacts/phase4/factory_db/deploy'))
    p.add_argument('--factory', type=Path,
                   default=Path('artifacts/phase2/filesystems/NAV/system/Data_base/sqlite'))
    a = p.parse_args()
    if a.output.exists():
        p.error('output exists; preserve prior experiments')
    plan = json.loads(a.plan.read_text())
    app = Path('artifacts/phase2/applications/NAV/app.bin').read_bytes()
    grouped = {}
    for op in plan['operations']:
        name = op['database']
        if Path(name).name != name or not name.endswith('.sqlite'):
            raise ValueError('invalid database name')
        grouped.setdefault(name, []).append(op)
    generated = {}; records = []
    for filename, operations in grouped.items():
        source = a.base / 'user_data/sqlite' / filename
        if not source.exists():
            source = a.factory / filename
        original = source.read_bytes()
        raw = gzip.decompress(original) if original[:2] == b'\x1f\x8b' else original
        c = sqlite3.connect(':memory:'); c.deserialize(raw)
        c.execute('PRAGMA trusted_schema=OFF')
        if c.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='trigger'").fetchone()[0]:
            raise ValueError('unexpected triggers; refusing implicit changes')
        if c.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
            raise ValueError('source database integrity failed')
        for op in operations:
            table, key, column, value = op['table'], op['key'], op['column'], op['value']
            if table == 'sw_option' and column == 'value' and set(key) == {'name'}:
                if key['name'].encode() + b'\0' not in app or value not in (0, 1):
                    raise ValueError('unverified option or boolean value')
                row = c.execute('SELECT value FROM sw_option WHERE name=?',
                                (key['name'],)).fetchall()
                if len(row) > 1:
                    raise ValueError('ambiguous option rows')
                before = row[0][0] if row else None
                sql = ('UPDATE sw_option SET value=? WHERE name=?' if row else
                       'INSERT INTO sw_option(value,name) VALUES(?,?)')
                parameters = [value, key['name']]
                kind = 'UPDATE' if row else 'INSERT'
            elif (filename == 'browser.sqlite' and table == 'preferences' and
                    column == 'homepage' and set(key) == {'id'} and key['id'] == 0):
                if not isinstance(value, str):
                    raise ValueError('homepage must be a string')
                row = c.execute('SELECT homepage FROM preferences WHERE id=?', (0,)).fetchall()
                if len(row) != 1:
                    raise ValueError('browser homepage row missing or ambiguous')
                before = row[0][0]
                sql = 'UPDATE preferences SET homepage=? WHERE id=?'
                parameters = [value, 0]; kind = 'UPDATE'
            elif table == 'UP_Keys' and set(key) == {'Section', 'Name', 'Idx'} and column in ('IntValue', 'StringValue'):
                suffix = ' WHERE Section=? AND Name=? AND Idx=?'
                keys = [key['Section'], key['Name'], key['Idx']]
                row = c.execute('SELECT Type,"' + column + '" FROM UP_Keys' + suffix,
                                keys).fetchall()
                if len(row) != 1:
                    raise ValueError('UP key missing or ambiguous: ' + str(key))
                if column == 'IntValue' and (not isinstance(value, int) or
                        (row[0][0] == 2 and value not in (0, 1))):
                    raise ValueError('invalid integer/boolean value')
                if column == 'StringValue' and not isinstance(value, str):
                    raise ValueError('invalid string value')
                before = row[0][1]
                sql = 'UPDATE UP_Keys SET "' + column + '"=?' + suffix
                parameters = [value] + keys; kind = 'UPDATE'
            else:
                raise ValueError('unsupported table, column, or key')
            if c.execute(sql, parameters).rowcount != 1:
                raise ValueError('expected exactly one changed row')
            records.append(dict(op, operation=kind, before=before, after=value,
                                sql=sql, parameters=parameters))
        c.commit()
        if c.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
            raise ValueError('modified integrity check failed')
        decoded = c.serialize(); c.close()
        if filename == 'browser.sqlite':
            # Browser opens a regular SQLite file. Native readback has no .inf;
            # the UP/config gzip envelope is not this database's storage API.
            if original[:16] != b'SQLite format 3\0' or source.with_name(filename+'.inf').exists():
                raise ValueError('unexpected native browser database envelope')
            stored, inf = decoded, None
        else:
            stored = gzip.compress(decoded, mtime=0)
            inf = encode_inf(decoded, stored); verify_inf(decoded, stored, inf)
        generated[filename] = (decoded, stored, inf)
        records.append({'operation': 'VALIDATE', 'database': filename,
            'source': str(source), 'source_sha256': hashlib.sha256(original).hexdigest(),
            'modified_raw_sha256': hashlib.sha256(decoded).hexdigest(),
            'integrity': 'ok', 'native_inf': inf.decode() if inf else None,
            'storage_format': 'gzip+native_inf' if inf else 'raw_sqlite'})
    shutil.copytree(a.base, a.output / 'deploy')
    target = a.output / 'deploy/user_data/sqlite'
    decoded_dir = a.output / 'decoded'; decoded_dir.mkdir()
    for filename, (raw, stored, inf) in generated.items():
        (target / filename).write_bytes(stored)
        if inf:
            (target / (filename + '.inf')).write_bytes(inf)
        (decoded_dir / filename).write_bytes(raw)
    (a.output / 'plan.json').write_text(json.dumps(plan, indent=2) + '\n')
    (a.output / 'flag_changes.log').write_text(''.join(json.dumps(r, sort_keys=True) + '\n' for r in records))
    print(json.dumps({'case': plan['name'], 'operations': len(plan['operations']),
                      'deployment': str(a.output / 'deploy')}))


if __name__ == '__main__':
    main()
