#!/usr/bin/env python3
"""Read original A9 NAV harmony windows; never change NAND or guest files."""
import argparse
import hashlib
import json
import struct
import zlib
from pathlib import Path


def inspect(package):
    results = []
    mapping_file = package / 'HARMONY/A9.bigharmony.ini'
    text = mapping_file.read_text().replace('\\n', '\n')
    mapping = next(line.split(':', 1)[1] for line in text.splitlines()
                   if line.startswith('LIST_NAV:'))
    for bank, group in enumerate(map(int, mapping.split(',')), 1):
        if not group:
            continue
        source = package / f'HARMONY/BigHarmony_{group}/BIG_HARMONY.bin'
        data = source.read_bytes()
        count, = struct.unpack_from('>I', data, 0x820)
        for entry in range(count):
            record = data[0x824 + entry * 216:0x824 + (entry + 1) * 216]
            page, size, crc = struct.unpack_from('>III', record, 0xcc)
            payload = data[page * 2048:page * 2048 + size]
            if zlib.crc32(payload) != crc:
                raise ValueError('Original compressed harmony CRC mismatch')
            expected, = struct.unpack_from('>I', payload)
            raw = zlib.decompress(payload[4:])
            if len(raw) != expected:
                raise ValueError('Original harmony expanded size mismatch')
            # Native loadApplicationFile021cf054..f8 reads16-byte records
            # starting+6c, and adds header+8 to each record's byte offset.
            n, base = struct.unpack_from('>II', raw, 4)
            if 0x6c + n * 16 > len(raw):
                raise ValueError('Window directory exceeds resource')
            windows = [struct.unpack_from('>4I', raw, 0x6c + i * 16)
                       for i in range(n)]
            target = next(w for w in windows if w[:2] == (20, 41))
            start = base + target[2]
            end = min([base + w[2] for w in windows if base + w[2] > start]
                      + [len(raw)])
            if not 0 <= start < end <= len(raw):
                raise ValueError('ASR window extent invalid')
            window = raw[start:end]
            dote = struct.pack('>I', 0x88f)
            positions = [hex(start + i) for i in range(0, len(window) - 3, 4)
                         if window[i:i + 4] == dote]
            results.append({
                'source': str(source),
                'source_sha256': hashlib.sha256(data).hexdigest(),
                'compressed_crc32_verified': f'{crc:08x}',
                'name': record[:196].split(b'\0')[0].decode('ascii'),
                'HMI_slot': struct.unpack_from('>I', record, 0xc8)[0],
                'HARMONY_code': bank * 100 + entry + 1,
                'native_window_app': 20, 'native_window_id': 41,
                'expanded_window_start': hex(start),
                'expanded_window_bytes_to_next': len(window),
                'window_sha256': hashlib.sha256(window).hexdigest(),
                'DOTE_text_index_0x88f_locations': positions,
                'contains_native_snow_image_id_0x3e9389':
                    struct.pack('>I', 0x3e9389) in raw,
                'interpretation': ('Original DOTE placeholder window' if positions
                                   else 'Original non-placeholder ASR window; runtime validation required'),
            })
    return results


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--package', type=Path,
                    default=Path('artifacts/phase2/package/SMEG_PLUS_UPG'))
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(inspect(args.package), indent=2) + '\n')
