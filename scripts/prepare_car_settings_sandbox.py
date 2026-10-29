#!/usr/bin/env python3
"""Apply captured runtime scalars to emulator DB templates, never a car backup.

Missing array contents and unobserved keys retain emulator values. These files
are deliberately stored under phase7 and must never be deployed to a vehicle.
"""
import argparse
import gzip
import hashlib
import json
import sqlite3
from pathlib import Path
from smeg_db_inf import encode_inf, verify_inf


def decode(path):
    raw = path.read_bytes()
    return gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inventory', type=Path, required=True)
    p.add_argument('--templates', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    inventory = json.loads(a.inventory.read_text())
    snapshots = [s for s in inventory['parameter_snapshots'] if s['user_parameter_groups']]
    snapshot = sorted(snapshots, key=lambda s: s['location'])[-1]
    a.output.mkdir(parents=True, exist_ok=False)
    destination = a.output / 'deploy/user_data/sqlite'
    destination.mkdir(parents=True)
    report = {'emulator_only': True, 'complete_car_backup': False,
              'source_capture': snapshot['location'], 'databases': {},
              'group_mapping': [], 'changes': [], 'unrecovered_arrays': [],
              'unmatched': [], 'software_options_without_database_row': {}}
    databases, keys = {}, {}
    for name in ('up_config', 'up_user', 'up_common', 'up_user_hmi'):
        src = a.templates / (name + '.sqlite')
        raw = decode(src)
        c = sqlite3.connect(':memory:')
        c.deserialize(raw)
        databases[name] = c
        keys[name] = {(s + '.' + n, i): (s, n, t)
                      for s, n, i, t in c.execute('SELECT Section,Name,Idx,Type FROM UP_Keys')}
        report['databases'][name] = {'template': str(src),
                                    'template_raw_sha256': hashlib.sha256(raw).hexdigest()}
    for i, group in enumerate(snapshot['user_parameter_groups']):
        observed = {(e['key'], e['index']) for e in group['entries']}
        matches = sorted(((len(observed & set(ks)), name) for name, ks in keys.items()), reverse=True)
        if len(matches) > 1 and matches[0][0] == matches[1][0]:
            raise ValueError('Ambiguous runtime parameter group')
        count, name = matches[0]
        report['group_mapping'].append({'group': i, 'database': name, 'matched': count,
                                        'observed': len(observed)})
        c = databases[name]
        for e in group['entries']:
            k = (e['key'], e['index'])
            if k not in keys[name]:
                report['unmatched'].append(e)
                continue
            section, key, kind = keys[name][k]
            if e['type'] == 'array':
                report['unrecovered_arrays'].append({'database': name, **e})
                continue
            if e['type'] in ('int', 'uint', 'bool'):
                if kind not in (1, 2): raise ValueError('Unexpected scalar type')
                column, value = 'IntValue', int(e['value'])
            elif e['type'] == 'string':
                if kind != 4: raise ValueError('Unexpected string type')
                # Stock ShowStatus surrounds strings with '-' delimiters.
                value = e['value']
                if not (value.startswith('-') and value.endswith('-')):
                    raise ValueError('Unexpected native string framing')
                column, value = 'StringValue', value[1:-1]
            else:
                raise ValueError('Unsupported captured type')
            before = c.execute(f'SELECT {column} FROM UP_Keys WHERE Section=? AND Name=? AND Idx=?',
                               (section, key, e['index'])).fetchone()[0]
            result = c.execute(f'UPDATE UP_Keys SET {column}=? WHERE Section=? AND Name=? AND Idx=?',
                               (value, section, key, e['index']))
            if result.rowcount != 1: raise ValueError('Nonunique parameter')
            report['changes'].append({'database': name, 'section': section, 'name': key,
                                      'index': e['index'], 'column': column,
                                      'before': before, 'after': value})
    for name, c in databases.items():
        c.commit()
        if c.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
            raise ValueError('Invalid resulting SQLite')
        raw = c.serialize()
        stored = gzip.compress(raw, mtime=0)
        inf = encode_inf(raw, stored)
        assert verify_inf(raw, stored, inf)
        (destination / (name + '.sqlite')).write_bytes(stored)
        (destination / (name + '.sqlite.inf')).write_bytes(inf)
        c.close()
    src = a.templates / 'config_options.sqlite'
    c = sqlite3.connect(':memory:'); c.deserialize(decode(src))
    for name, value in snapshot['software_options'].items():
        result = c.execute('UPDATE sw_option SET value=? WHERE name=?', (value, name))
        if result.rowcount == 0:
            # Many reported options are computed/build constants, not DB rows.
            report['software_options_without_database_row'][name] = value
        elif result.rowcount != 1:
            raise ValueError('Nonunique software option ' + name)
    c.commit(); raw = c.serialize(); c.close()
    stored = gzip.compress(raw, mtime=0)
    inf = encode_inf(raw, stored)
    assert verify_inf(raw, stored, inf)
    (destination / 'config_options.sqlite').write_bytes(stored)
    (destination / 'config_options.sqlite.inf').write_bytes(inf)
    report['software_options_applied'] = {k: v for k, v in snapshot['software_options'].items()
                                        if k not in report['software_options_without_database_row']}
    report['preserved_unobserved_common_rows'] = len(keys['up_common']) - sum(
        m['matched'] for m in report['group_mapping'] if m['database'] == 'up_common')
    (a.output / 'provenance.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'output': str(a.output), 'scalar_entries_applied': len(report['changes']),
                      'arrays_preserved_from_emulator': len(report['unrecovered_arrays']),
                      'unmatched': len(report['unmatched']), 'emulator_only': True}))


if __name__ == '__main__':
    main()
