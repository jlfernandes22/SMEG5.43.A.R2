#!/usr/bin/env python3
"""Read-only audit of a stopped native-updater sandbox; never install anything.

The native log's unconditional USER_DATA success message is not evidence of a
copy. This checks actual stored bytes and all seven original database contents.
Raw-container absence is inconclusive if the installer changes storage layout;
it cannot be treated as a successful persistent installation.
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
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'emulation'))
from inject_volume import discover, mappings, bpb, extract
from smeg_db_inf import verify_inf

BACKUP = ROOT / 'artifacts/live_car_backup/2026-10-27-native-usb'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def native_payload(path):
    data = path.read_bytes()
    if path.name != 'BIG_HARMONY.bin':
        return data
    # The native installer replaces the first page, unlike BigQuick. This is
    # the recovered WriteBigHarmony storage format used by seed_harmony.py;
    # comparing the entire source container verbatim would always fail.
    text = Path(str(path) + '.inf').read_text().replace('\\n', '\n')
    fields = dict(line.split(':', 1) for line in text.splitlines() if ':' in line)
    header = bytearray(0xa8)
    for offset, text in [(0, 'BIGHARMONY'), (0x20, '0.540.0'),
        (0x40, fields['VERSION_BIGHARMONY_STRUCT']), (0x60, fields['DATE']),
        (0x80, fields['VERSION'])]:
        value = text.encode('ascii')
        assert len(value) < 32
        header[offset:offset + len(value)] = value
    struct.pack_into('>II', header, 0xa0, int(fields['HEADER_SIZE']), int(fields['HEADER_CRC32']) & 0xffffffff)
    return bytes(header) + b'\xff' * (2048 - len(header)) + data[2048:]


def rows(stored):
    data = gzip.decompress(stored) if stored[:2] == b'\x1f\x8b' else stored
    conn = sqlite3.connect(':memory:')
    conn.deserialize(data)
    conn.execute('PRAGMA trusted_schema=OFF')
    assert conn.execute('PRAGMA integrity_check').fetchall() == [('ok',)]
    result = {}
    for name, sql in conn.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"):
        quoted = '"' + name.replace('"', '""') + '"'
        result[name] = (sql, conn.execute('SELECT * FROM ' + quoted).fetchall())
    conn.close()
    return data, result


def expected_database_source(package, original):
    """Only the two explicitly customized DBs may use candidate expectations.

    Other databases continue to compare directly with the original car export.
    A byte-exact stock copy also records the original export as its expectation.
    """
    candidate = package / 'NAV/USER_DATA/user_data/sqlite' / original.name
    expected = (candidate if original.name in ('up_config.sqlite', 'up_common.sqlite')
                and candidate.is_file() else original)
    assert not expected.is_symlink() and stat.S_ISREG(expected.stat().st_mode)
    if expected.read_bytes() == original.read_bytes():
        expected = original
    return expected


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--nand', type=Path, required=True)
    p.add_argument('--package', type=Path, required=True)
    p.add_argument('--user-base-page', type=int, required=True)
    p.add_argument('--stopped-prefix', required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    assert a.stopped_prefix.startswith('/tmp/smeg-')
    assert not Path(a.stopped_prefix + '.qmp').exists(), 'Stop the matching VM first'
    assert not a.nand.is_symlink() and stat.S_ISREG(a.nand.stat().st_mode)
    assert a.nand.resolve().is_relative_to(ROOT / 'artifacts')
    allowed = [ROOT / 'artifacts' / phase for phase in ('phase13', 'phase14', 'phase15')]
    assert any(a.package.resolve().is_relative_to(path) for path in allowed)
    assert any(a.output.resolve().is_relative_to(path) for path in allowed) and not a.output.exists()
    report = {'physical_device_access': False, 'guest_memory_writes': False,
              'nand': str(a.nand), 'package': str(a.package), 'raw_containers': [],
              'databases': [], 'native_installation_verified': False,
              'cold_boot_UI_verified': False, 'PAN_or_DUN_connection_verified': False}
    with a.nand.open('rb') as stream:
        report['nand_sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
    targets = [a.package / 'AUDIO_BT_256/AppBin/f_BigQuick.bin']
    targets += [a.package / f'HARMONY/BigHarmony_{n}/BIG_HARMONY.bin' for n in (4, 5)]
    with a.nand.open('rb') as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        assert len(mm) % 2112 == 0
        for target in targets:
            expected = native_payload(target)
            found = []
            offset = 0
            while True:
                offset = mm.find(expected[:128], offset)
                if offset < 0:
                    break
                page, column = divmod(offset, 2112)
                offset += 1
                if column or (page + (len(expected) + 2047) // 2048) * 2112 > len(mm):
                    continue
                actual = b''.join(mm[i * 2112:i * 2112 + min(2048, len(expected) - (i - page) * 2048)]
                                  for i in range(page, page + (len(expected) + 2047) // 2048))
                match = {'logical_offset': hex(page * 2048), 'sha256': sha(actual),
                         'exact_payload_match': actual == expected}
                if target.name == 'BIG_HARMONY.bin':
                    # Native WriteBigHarmony writes a168-byte preheader.
                    # Its page tail is uninitialized by WriteNand_Buffer;
                    # ReadBigHarmonyPreHeader reads only168bytes. Header CRC
                    # begins in the following page, outside this padding.
                    regions = {}
                    for name, start, length in [('metadata', 0, 168), ('body', 2048, len(expected)-2048)]:
                        regions[name] = {'offset': start, 'length': length,
                            'actual_sha256': sha(actual[start:start+length]),
                            'expected_sha256': sha(expected[start:start+length])}
                    regions['padding'] = {'offset': 168, 'length': 1880,
                                          'indeterminate': True}
                    match['native_defined_regions'] = regions
                    match['native_defined_regions_match'] = all(
                        regions[name]['actual_sha256'] == regions[name]['expected_sha256']
                        for name in ('metadata', 'body'))
                found.append(match)
            report['raw_containers'].append({'path': str(target.relative_to(a.package)),
                                            'source_sha256': sha(target.read_bytes()),
                                            'storage_format': ('native BIGHARMONY preheader plus original source[2048:]'
                                                               if target.name == 'BIG_HARMONY.bin' else 'original BigQuick bytes'),
                                            'expected_stored_sha256': sha(expected), 'matches': found})
        selected = [(key, h) for key, h in discover(mm).items()
                    if min(x['page'] for x in h) == a.user_base_page]
        if len(selected) != 1:
            report['filesystem_error'] = 'Ambiguous or missing USER_DATA volume'
            finish_report(report, a.output)
            raise SystemExit(2)
        key, headers = selected[0]
        latest, _ = mappings(mm, headers, key[2])
        fs = bpb(mm, latest)
        if not fs:
            report['filesystem_error'] = 'No native USER_DATA filesystem'
            finish_report(report, a.output)
            raise SystemExit(2)
        with tempfile.TemporaryDirectory(prefix='smeg-native-audit-') as d:
            d = Path(d)
            fat = d / 'user.fat'
            fat.write_bytes(extract(mm, latest, fs['sectors']))
            env = dict(os.environ, MTOOLS_SKIP_CHECK='1')
            for original in sorted((BACKUP / 'usb/SMEG_BACKUP').glob('*.sqlite')):
                name = original.name
                record = {'name': name, 'present': False}
                report['databases'].append(record)
                stored = []
                for suffix in ('', '.inf'):
                    output = d / (name + suffix)
                    result = subprocess.run(['mcopy', '-i', str(fat),
                        '::/user_data/sqlite/' + name + suffix, str(output)], env=env, capture_output=True)
                    if result.returncode:
                        record['read_error'] = result.stderr.decode(errors='replace')
                        break
                    stored.append(output.read_bytes())
                if len(stored) != 2:
                    continue
                record['present'] = True
                raw, actual = rows(stored[0])
                record['native_INF_valid'] = bool(verify_inf(raw, stored[0], stored[1]))
                expected_path = expected_database_source(a.package, original)
                _, expected = rows(expected_path.read_bytes())
                record.update(stored_sha256=sha(stored[0]), sqlite_integrity='ok',
                              expected_database_contents_match=actual == expected,
                              expected_source=str(expected_path))
    with a.nand.open('rb') as stream:
        assert hashlib.file_digest(stream, 'sha256').hexdigest() == report['nand_sha256'], 'NAND changed during stopped audit'
    finish_report(report, a.output)


def finish_report(report, output):
    """Keep failed-storage evidence too; absent filesystems are never a pass."""
    report['all_seven_database_contents_verified'] = len(report['databases']) == 7 and all(
        r.get('native_INF_valid') and r.get('expected_database_contents_match') for r in report['databases'])
    report['all_three_raw_container_bytes_verified'] = len(report['raw_containers']) == 3 and all(
        any(m['exact_payload_match'] for m in r['matches']) for r in report['raw_containers'])
    report['all_three_raw_container_defined_regions_verified'] = len(report['raw_containers']) == 3 and all(
        any(m.get('native_defined_regions_match', m['exact_payload_match']) for m in r['matches'])
        for r in report['raw_containers'])
    # Stored bytes alone cannot establish HOW they got there: an offline
    # control can have exactly the same bytes as a native-updater result.
    report['stored_candidate_bytes_and_databases_verified'] = (
        report['all_seven_database_contents_verified'] and report['all_three_raw_container_bytes_verified'])
    report['stored_defined_payload_regions_and_databases_verified'] = (
        report['all_seven_database_contents_verified'] and report['all_three_raw_container_defined_regions_verified'])
    report['native_installation_verified'] = False
    report['verification_scope'] = 'Read-only stored state only; installation provenance and cold-boot UI require separate evidence.'
    output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ['stored_candidate_bytes_and_databases_verified', 'native_installation_verified',
        'all_seven_database_contents_verified', 'all_three_raw_container_bytes_verified',
        'cold_boot_UI_verified', 'PAN_or_DUN_connection_verified']}))


if __name__ == '__main__':
    main()
