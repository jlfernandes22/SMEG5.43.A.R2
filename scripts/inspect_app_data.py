#!/usr/bin/env python3
"""Read-only package audit; extract only previously unextracted second app segments."""
import argparse
import gzip
import hashlib
import json
import re
import sqlite3
import struct
import sys
import zlib
from pathlib import Path


def digest(data):
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'crc32': f'{zlib.crc32(data):08x}'}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root', type=Path, default=Path('artifacts/phase2'))
    ap.add_argument('--tools', type=Path, default=Path('sources/smeg-plus-patches/tools'))
    args = ap.parse_args()
    root = args.root
    package = root / 'package/SMEG_PLUS_UPG'
    sys.path.insert(0, str(args.tools.resolve()))
    from verify_package import audit
    report = {'package_problems': audit(str(package)), 'applications': [], 'databases': [],
              'notes': ['No package files, original application files, or databases are modified.',
                        'CRC32 and zlib checks establish internal integrity, not authenticity.',
                        'Second segment runtime purpose/load address is not established by this audit.']}
    manifest = json.loads((root / 'payload-manifest.json').read_text())
    for p in sorted(package.rglob('f_BigQuick.bin')):
        raw = p.read_bytes()
        words = [struct.unpack_from('>8I', raw, i * 32) for i in range(64)]
        module = p.relative_to(package).parts[0]
        entry = {'module': module, 'container': digest(raw),
                 'header_used_entries': [{'index': i, 'words_hex': [f'{w:08x}' for w in ws]}
                                         for i, ws in enumerate(words) if ws != (0xdeadbeef,) * 8],
                 'unused_deadbeef_entries': sum(ws == (0xdeadbeef,) * 8 for ws in words),
                 'segments': []}
        offsets = [0x800, (words[1][0] + 1) * 2048]
        ends = []
        for index, offset in enumerate(offsets):
            if raw[offset] != 8:
                raise ValueError('missing compression marker')
            d = zlib.decompressobj()
            image = d.decompress(raw[offset + 1:]) + d.flush()
            if not d.eof:
                raise ValueError('incomplete zlib stream')
            end = len(raw) - len(d.unused_data)
            ends.append(end)
            segment = {'index': index, 'marker_offset': offset, 'zlib_offset': offset + 1,
                       'zlib_end_exclusive': end, 'compressed_bytes': end - offset - 1,
                       'header_inflated_size': words[index][1],
                       'inflated_size_matches_header': len(image) == words[index][1],
                       'header_stored_span': words[index][5],
                       'stored_span_equals_marker_plus_zlib_plus_two': words[index][5] == end - offset + 2,
                       **digest(image)}
            destination = root / 'applications' / module / ('app.bin' if index == 0 else 'app_segment2.bin')
            if index == 0:
                segment['existing_app_matches'] = destination.read_bytes() == image
                recorded = next(v for v in manifest if v['source'] == str(p.relative_to(package)))
                segment['payload_manifest_matches'] = all(segment[k] == recorded[k] for k in ('sha256', 'crc32')) and segment['bytes'] == recorded['size']
            elif destination.exists():
                if destination.read_bytes() != image:
                    raise ValueError('refusing to replace different existing second segment')
            else:
                destination.write_bytes(image)
            segment['output'] = str(destination)
            entry['segments'].append(segment)
        entry['between_zlib_streams'] = digest(raw[ends[0]:offsets[1]])
        entry['between_streams_first16_hex'] = raw[ends[0]:ends[0] + 16].hex()
        entry['first_stream_two_byte_suffix_hex'] = raw[ends[0]:ends[0] + 2].hex()
        entry['gap_after_two_byte_suffix_is_all_ee'] = set(raw[ends[0] + 2:offsets[1]]) == {0xee}
        entry['bytes_after_second_zlib'] = len(raw) - ends[1]
        entry['after_second_zlib_hex'] = raw[ends[1]:].hex()
        sidecar = (p.parent / (p.name + '.inf')).read_text()
        declared = re.search(r'CRC32:\s*(-?\d+)', sidecar)
        entry['container_sidecar_crc_matches'] = declared is not None and (int(declared[1]) & 0xffffffff) == zlib.crc32(raw)
        report['applications'].append(entry)
    for p in sorted((root / 'filesystems').rglob('*.sqlite')):
        original = p.read_bytes()
        data = gzip.decompress(original) if original.startswith(b'\x1f\x8b') else original
        item = {'path': str(p), 'module': p.relative_to(root / 'filesystems').parts[0],
                'gzip_wrapped': data is not original, **digest(original), 'tables': []}
        if not data.startswith(b'SQLite format 3\0'):
            item['error'] = 'not SQLite after optional gzip decode'
            report['databases'].append(item)
            continue
        if data is original:
            conn = sqlite3.connect(p.resolve().as_uri() + '?mode=ro&immutable=1', uri=True)
        else:
            conn = sqlite3.connect(':memory:')
            conn.deserialize(data)
        with conn:
            conn.execute('PRAGMA query_only=ON')
            conn.execute('PRAGMA trusted_schema=OFF')
            for name, sql in conn.execute("SELECT name,sql FROM sqlite_schema WHERE type='table' ORDER BY name"):
                table = {'name': name, 'sql': sql,
                         'columns': [{'name': r[1], 'type': r[2]} for r in conn.execute('SELECT * FROM pragma_table_info(?)', (name,))]}
                if p.name in ('config_options.sqlite', 'up_config.sqlite', 'config.sqlite'):
                    quoted = '"' + name.replace('"', '""') + '"'
                    table['row_count'] = conn.execute('SELECT COUNT(*) FROM ' + quoted).fetchone()[0]
                    if p.name == 'up_config.sqlite' and name == 'UP_Keys':
                        table['feature_key_candidates'] = [dict(zip(('Section', 'Name', 'Type', 'Idx', 'IntValue'), row))
                            for row in conn.execute("SELECT Section,Name,Type,Idx,IntValue FROM UP_Keys WHERE lower(Section || ' ' || Name) LIKE '%stop%' OR lower(Section || ' ' || Name) LIKE '%nav%' OR lower(Section || ' ' || Name) LIKE '%app%' OR lower(Section || ' ' || Name) LIKE '%carplay%' OR lower(Section || ' ' || Name) LIKE '%android%'")]
                item['tables'].append(table)
        conn.close()
        report['databases'].append(item)
    (root / 'app-data-evidence.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'package_problems': report['package_problems'], 'applications': len(report['applications']),
                      'databases': len(report['databases']), 'schema_errors': sum('error' in d for d in report['databases'])}))


if __name__ == '__main__':
    main()
