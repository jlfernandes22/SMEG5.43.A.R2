#!/usr/bin/env python3
"""Read-only, fail-closed audit of a stopped WARMLIGHT-only emulator test.

This checks actual stored databases and stock code/resources, not UI success or
physical compatibility. Both inputs must be stopped regular workspace images.
"""
import argparse
import gzip
import hashlib
import json
import mmap
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'emulation'))
from inject_volume import discover, mappings, bpb, extract
from audit_usb_single_key import read_db, difference
from audit_persistent_candidate import native_payload

BACKUP = ROOT / 'artifacts/live_car_backup/2026-10-27-native-usb/usb/SMEG_BACKUP'
FACTORY = ROOT / 'artifacts/phase2/package/SMEG_PLUS_UPG'
BASELINE_SHA = '876478b234d36d92dcb5ab989ee81a3a1c2977f5f39c286eb2922bd9edc5a894'
ENV = dict(os.environ, MTOOLS_SKIP_CHECK='1')
TARGETS = (
    ('AUDIO_BT_256/AppBin/f_BigQuick.bin', 0x1100000,
     'c3f329c0d56c4a1726b097ccd55a0eaf44f6ece0a14018886d146b09e47ccfa2'),
    ('HARMONY/BigHarmony_4/BIG_HARMONY.bin', 0x2dc0000,
     '50b767967a9d4ee83b183210a00f335ec85701829d06ca57d9e239d36d3bbfea'),
    ('HARMONY/BigHarmony_5/BIG_HARMONY.bin', 0x4f60000,
     '266ef132ede2b9c05c698f504d00911433f897aead811fba79bb79cbd407a8df'),
)
NATIVE_HARMONY_ENDINGS = (b'', b'\x00', b'\r\n', b'\n', b'\r\n\x00', b'\x00\r\n')


def require(condition, text):
    if not condition:
        raise ValueError(text)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def regular(path):
    require(not path.is_symlink() and path.resolve().is_relative_to(ROOT / 'artifacts'),
            'Regular workspace artifact required')
    require(stat.S_ISREG(path.stat().st_mode) and path.stat().st_size == 276824064,
            'Expected regular 256 MiB NAND plus OOB image')


def no_visible_writer(path):
    """Reject observed writable FDs; this is a check, not a universal OS lock."""
    identity = path.stat()
    writers = []
    for process in Path('/proc').iterdir():
        if not process.name.isdigit():
            continue
        try:
            for fd in (process / 'fd').iterdir():
                try:
                    info = fd.stat()
                    if (info.st_dev, info.st_ino) != (identity.st_dev, identity.st_ino):
                        continue
                    lines = (process / 'fdinfo' / fd.name).read_text().splitlines()
                    flags = next(int(x.split()[1], 8) for x in lines if x.startswith('flags:'))
                    if flags & os.O_ACCMODE != os.O_RDONLY:
                        writers.append({'pid': int(process.name), 'fd': fd.name})
                except (OSError, StopIteration):
                    continue
        except OSError:
            continue
    require(not writers, 'Image still has a visible live writer: ' + str(writers))


def schema(stored):
    raw = gzip.decompress(stored) if stored[:2] == b'\x1f\x8b' else stored
    db = sqlite3.connect(':memory:')
    try:
        db.deserialize(raw)
        return db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master "
                          "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").fetchall()
    finally:
        db.close()


def read_member(fat, name, work, label):
    target = work / label
    proc = subprocess.run(['mcopy', '-i', str(fat), '::/' + name, str(target)],
                          capture_output=True, env=ENV)
    require(proc.returncode == 0, 'Missing native member ' + name + ': ' +
            proc.stderr.decode(errors='replace'))
    return target.read_bytes()


def read_snapshot(path, work, label, observe=False):
    result = {'path': str(path), 'sha256': digest(path), 'containers': [], 'databases': {}}
    with path.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        for relative, logical, original_sha in TARGETS:
            source = FACTORY / relative
            require(digest(source) == original_sha, 'Original factory file changed: ' + relative)
            expected = native_payload(source)
            first = logical // 2048
            actual = b''.join(mm[page * 2112:page * 2112 + min(2048, len(expected) -
                           (page - first) * 2048)]
                           for page in range(first, first + (len(expected) + 2047) // 2048))
            item = {'path': relative, 'logical_offset': hex(logical), 'actual_sha256': sha(actual),
                    'expected_stored_sha256': sha(expected), 'full_native_payload_exact': actual == expected}
            fields = dict(line.split(':', 1) for line in Path(str(source) + '.inf').read_text().splitlines() if ':' in line)
            if source.name == 'BIG_HARMONY.bin':
                item['defined_regions_exact'] = actual[:168] == expected[:168] and actual[2048:] == expected[2048:]
                item['padding'] = {'offset': 168, 'length': 1880,
                                   'sha256': sha(actual[168:2048]),
                                   'matches_stock_erased_padding': actual[168:2048] == expected[168:2048]}
                length = int(fields['HEADER_SIZE'])
                item['native_header_CRC32'] = {
                    'expected': int(fields['HEADER_CRC32']) & 0xffffffff,
                    'actual': zlib.crc32(actual[2048:2048 + length]),
                    'valid': zlib.crc32(actual[2048:2048 + length]) == int(fields['HEADER_CRC32']) & 0xffffffff}
            else:
                item['native_payload_CRC32'] = {
                    'expected': int(fields['CRC32']) & 0xffffffff,
                    'actual': zlib.crc32(actual),
                    'valid': zlib.crc32(actual) == int(fields['CRC32']) & 0xffffffff}
            if not observe:
                require(actual == expected, 'Stock container differs: ' + label + ': ' + relative)
            result['containers'].append(item)
        groups = discover(mm)
        for volume, base in [('USER_DATA', 103168), ('SYSTEM_DATA', 57856)]:
            found = [(k, h) for k, h in groups.items() if min(x['page'] for x in h) == base]
            require(len(found) == 1, 'Native volume absent/ambiguous: ' + volume)
            key, headers = found[0]
            latest, _ = mappings(mm, headers, key[2])
            fs = bpb(mm, latest)
            require(fs is not None, 'Native FAT absent: ' + volume)
            fat = work / (label + '-' + volume + '.fat')
            fat.write_bytes(extract(mm, latest, fs['sectors']))
            if volume == 'SYSTEM_DATA':
                result['Harmony.ini'] = read_member(fat, 'Harmony.ini', work, label + '-Harmony.ini')
                continue
            for original in sorted(BACKUP.glob('*.sqlite')):
                name = original.name
                stored = read_member(fat, 'user_data/sqlite/' + name, work, label + '-' + name)
                inf = read_member(fat, 'user_data/sqlite/' + name + '.inf', work, label + '-' + name + '.inf')
                record = {'stored_sha256': sha(stored), 'inf_sha256': sha(inf)}
                try:
                    record.update(schema=schema(stored), rows=read_db(stored, inf),
                                  sqlite_integrity_and_INF_valid=True)
                except (AssertionError, ValueError, sqlite3.Error, gzip.BadGzipFile, EOFError, zlib.error) as exc:
                    if not observe:
                        raise
                    record.update(sqlite_integrity_and_INF_valid=False,
                                  validation_error=type(exc).__name__ + ': ' + str(exc))
                result['databases'][name] = record
    require(len(result['databases']) == 7, 'Expected seven original car databases')
    return result


def key_value(data, section, name):
    table = data['UP_Keys']
    selected = [x for x in table['rows'] if x['Section'] == section and x['Name'] == name and x['Idx'] == 0]
    require(len(selected) == 1, 'Expected one exact existing key ' + section + '.' + name)
    return selected[0]


def harmony_matches(stored, value):
    """Accept exact native ASCII value with one documented text terminator.

    The observed native selector writes a single NUL after its ASCII value.
    Plain and CRLF/LF text files are also recognized; do not strip arbitrary
    whitespace, repeated NULs, extra fields, or data following a terminator.
    """
    text = ('HARMONY=' + str(value)).encode('ascii')
    return any(stored == text + ending for ending in NATIVE_HARMONY_ENDINGS)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--before', type=Path, required=True)
    parser.add_argument('--after', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--selected', action='store_true', help='Also allow only native WARMLIGHT selection')
    parser.add_argument('--baseline-only', action='store_true', help='Validate unchanged stock baseline, with no setter expected')
    parser.add_argument('--observe-differences', action='store_true',
                        help='Write complete observed differences; retain failed strict preservation and exit1 on unexpected changes')
    args = parser.parse_args()
    require(not (args.baseline_only and args.selected), 'Choose baseline-only or selected')
    for path in (args.before, args.after):
        regular(path)
        no_visible_writer(path)
    require(args.output.resolve().is_relative_to(ROOT / 'artifacts') and not args.output.exists(),
            'New workspace report path required')
    require(digest(args.before) == BASELINE_SHA, 'Before image is not the reviewed original stock256 source')
    initial = {str(path): digest(path) for path in (args.before, args.after)}
    with tempfile.TemporaryDirectory(prefix='smeg-warmlight-audit-') as tmp:
        before = read_snapshot(args.before, Path(tmp), 'before')
        after = read_snapshot(args.after, Path(tmp), 'after', args.observe_differences)
    changes = []
    unexpected = []
    for name, b in before['databases'].items():
        original = BACKUP / name
        original_stored = original.read_bytes()
        original_rows = read_db(original_stored, Path(str(original) + '.inf').read_bytes())
        require(not difference(original_rows, b['rows']), 'Before data differs from original car: ' + name)
        require(schema(original_stored) == b['schema'], 'Before schema differs from original car: ' + name)
        a = after['databases'][name]
        if not a.get('sqlite_integrity_and_INF_valid'):
            unexpected.append('Database validation failed: ' + name)
            changes.append({'database': name, 'sqlite_integrity_and_INF_valid': False,
                            'validation_error': a.get('validation_error')})
            continue
        schema_same = a['schema'] == b['schema']
        if not schema_same:
            unexpected.append('Schema changed: ' + name)
        expected = json.loads(json.dumps(b['rows']))
        if name == 'up_config.sqlite':
            row = key_value(expected, 'display', 'Harm_11')
            require(row['Type'] == 2 and row['IntValue'] == 0, 'Stock Harm_11 must be bool false')
            if not args.baseline_only:
                row['IntValue'] = 1
        if name == 'up_common.sqlite' and args.selected:
            row = key_value(expected, 'display_configuration', 'Display_Color')
            require(row['Type'] == 1 and row['IntValue'] == 10, 'Stock Display_Color must be10')
            row['IntValue'] = 11
        diff = difference(b['rows'], a['rows'])
        unexpected_diff = difference(expected, a['rows'])
        if unexpected_diff:
            unexpected.append('Unapproved database change: ' + name)
        changes.append({'database': name, 'sqlite_integrity_and_INF_valid': True,
                        'schema_unchanged': schema_same, 'changes': diff,
                        'unexpected_changes_from_strict_expected': unexpected_diff,
                        'observed_schema': a['schema'], 'original_schema': b['schema'],
                        'stored_bytes_unchanged': b['stored_sha256'] == a['stored_sha256'],
                        'sidecar_bytes_unchanged': b['inf_sha256'] == a['inf_sha256']})
    require(harmony_matches(before['Harmony.ini'], 101), 'Stock Harmony must be101')
    wanted = 201 if args.selected else 101
    if not harmony_matches(after['Harmony.ini'], wanted):
        unexpected.append('Unexpected native Harmony.ini selection')
    raw_exact = all(x['full_native_payload_exact'] for x in after['containers'])
    if not raw_exact:
        unexpected.append('One or more stock raw containers differ')
    if unexpected and not args.observe_differences:
        raise ValueError('; '.join(unexpected))
    for path in (args.before, args.after):
        no_visible_writer(path)
        require(digest(path) == initial[str(path)], 'Input changed during audit')
    report = {'scope': 'Stopped regular-file emulator images; no physical access or writes',
        'physical_device_access': False, 'physical_compatibility_verified': False,
        'UI_verified_by_this_auditor': False, 'mode': 'baseline-only' if args.baseline_only else 'selected' if args.selected else 'flag-only',
        'before': {k: v for k, v in before.items() if k not in ('databases', 'Harmony.ini')},
        'after': {k: v for k, v in after.items() if k not in ('databases', 'Harmony.ini')},
        'Harmony.ini': {'before': before['Harmony.ini'].decode('ascii', errors='backslashreplace'),
                        'after': after['Harmony.ini'].decode('ascii', errors='backslashreplace'),
                        'before_raw_hex': before['Harmony.ini'].hex(),
                        'after_raw_hex': after['Harmony.ini'].hex(),
                        'expected_logical_value': wanted,
                        'native_logical_value_matches': harmony_matches(after['Harmony.ini'], wanted),
                        'accepted_terminator_hex': [x.hex() for x in NATIVE_HARMONY_ENDINGS],
                        'normalization': 'Exact ASCII HARMONY=<expected> plus one allowed ending; no arbitrary strip'},
        'databases': changes,
        'all_seven_original_database_SQLite_integrity_and_INF_valid': all(x['sqlite_integrity_and_INF_valid'] for x in changes),
        'all_seven_original_database_schemas_preserved': all(x.get('schema_unchanged', False) for x in changes),
        'all_seven_original_database_rows_except_explicit_targets_preserved': not any(x.get('unexpected_changes_from_strict_expected') for x in changes) and all(x['sqlite_integrity_and_INF_valid'] for x in changes),
        'all_three_raw_stock_containers_byte_exact': raw_exact,
        'strict_single_flag_preservation': not unexpected,
        'observe_differences_mode': args.observe_differences,
        'unexpected_preservation_findings': unexpected,
        'inputs_unchanged': True,
        'writer_check_scope': 'Reject visible writable /proc FDs before and after; not a universal OS lock',
        'unmeasured': ['Other generated databases and files outside the seven original DBs plus Harmony.ini',
                       'Physical NAND, MCU, graphics or power-loss recovery']}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'output': str(args.output), 'mode': report['mode'],
                      'strict_single_flag_preservation': not unexpected,
                      'all_three_raw_stock_containers_byte_exact': raw_exact,
                      'database_changes': [x for x in changes if x.get('changes')]}))
    if unexpected:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
