#!/usr/bin/env python3
"""Artifact-only main-selector window append experiment for five old themes.

This deliberately does NOT claim shared-image/font/animation compatibility.
It appends the known Square selector, preserving all original shared pools and
all other windows byte-exact. A private QEMU run must determine dependencies.
Never mutates an existing candidate, original firmware, NAND or physical media.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import shutil
import struct
import zlib

from inspect_internet_harmony import ROOT, PAGE, SLOT_SIZE
from prepare_all_theme_assets import seal_inf, parse_candidate

TARGETS = {'GRAPHIC', 'ELLIPTIC', 'CUBIC', 'REFLEX', 'ESSENTIEL'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def windows(raw):
    count, base = struct.unpack_from('>II', raw, 4)
    assert 0x6c + count * 16 <= base <= len(raw)
    rows = [struct.unpack_from('>4I', raw, 0x6c + 16 * i) for i in range(count)]
    starts = sorted({base + row[2] for row in rows})
    assert starts and starts[0] >= base and starts[-1] < len(raw)
    # All windows precede the first manager resource table.
    boundary = struct.unpack_from('>I', raw, 16)[0]
    assert starts[-1] < boundary <= len(raw)
    ends = {start: end for start, end in zip(starts, starts[1:] + [boundary])}
    result = {}
    for i, row in enumerate(rows):
        key = row[:2]
        assert key not in result
        start = base + row[2]
        result[key] = {'directory_index': i, 'record': row, 'start': start,
                       'bytes': raw[start:ends[start]]}
    return base, result


def append_selector(raw, donor):
    base, old_windows = windows(raw)
    target = old_windows[255, 68]
    assert len(target['bytes']) == 608 and b'\0\0\x08\x8f' in target['bytes']
    assert len(donor) == 31968 and b'\0\0\x08\x8f' not in donor
    assert struct.unpack_from('>I', raw)[0] == len(raw)
    start = (len(raw) + 15) & ~15
    result = bytearray(raw + b'\0' * (start - len(raw)) + donor)
    struct.pack_into('>I', result, 0, len(result))
    directory_word = 0x6c + target['directory_index'] * 16 + 8
    struct.pack_into('>I', result, directory_word, start - base)
    # Every original byte except these two explicit u32s must survive.
    permitted = set(range(4)) | set(range(directory_word, directory_word + 4))
    assert all(left == right or i in permitted for i, (left, right) in enumerate(zip(raw, result)))
    assert result[12:0x6c] == raw[12:0x6c]  # every manager offset/size unchanged
    # Check original non-target fragments directly: appended target is beyond
    # shared pools, so a simplistic sorted-window parser is no longer valid.
    assert all(bytes(result[row['start']:row['start'] + len(row['bytes'])]) == row['bytes']
               for key, row in old_windows.items() if key != (255, 68))
    assert bytes(result[start:start + len(donor)]) == donor
    return bytes(result), {'old_window_bytes': len(target['bytes']), 'new_window_bytes': len(donor),
        'old_window_sha256': sha(target['bytes']), 'new_window_sha256': sha(donor),
        'old_expanded_bytes': len(raw), 'new_expanded_bytes': len(result),
        'appended_window_absolute_offset': start, 'directory_offset_field': directory_word,
        'new_relative_window_offset': start - base, 'old_window_left_unreferenced_intact': True,
        'all_other_windows_original_bytes_preserved': True, 'all_original_shared_tables_and_offsets_preserved': True,
        'shared_dependency_compatibility_verified': False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--assets', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    source, out = a.assets.resolve(), a.output.resolve()
    allowed = ROOT / 'artifacts/phase15/theme-assets'
    assert source.is_relative_to(allowed) and out.is_relative_to(allowed) and not out.exists()
    manifest = json.loads((source / 'manifest.json').read_text())
    assert len(manifest['files']) == 12
    for item in manifest['files']:
        path = source / 'overlay' / item['path']
        assert not path.is_symlink() and path.is_file()
        data = path.read_bytes()
        assert len(data) == item['bytes'] and sha(data) == item['SHA256']
    donor_bank = (source / 'overlay/HARMONY/BigHarmony_4/BIG_HARMONY.bin').read_bytes()
    record = donor_bank[PAGE + 36:PAGE + 36 + 216]
    assert record[:196].split(b'\0')[0] == b'SQUARE'
    page, size, crc = struct.unpack_from('>III', record, 204)
    payload = donor_bank[page * PAGE:page * PAGE + size]
    assert zlib.crc32(payload) == crc
    donor_raw = zlib.decompress(payload[4:])
    _, donor_windows = windows(donor_raw)
    donor = donor_windows[255, 68]['bytes']
    out.mkdir(parents=True)
    shutil.copytree(source / 'overlay', out / 'overlay')
    changed = []
    revised = copy.deepcopy(manifest)
    for bank in revised['banks']:
        target = out / 'overlay/HARMONY' / ('BigHarmony_' + str(bank['target_group'])) / 'BIG_HARMONY.bin'
        original = target.read_bytes()
        count = struct.unpack_from('>I', original, PAGE + 32)[0]
        prefix = bytearray(original[:2 * PAGE])
        payloads = bytearray()
        cursor = 2
        for index in range(count):
            position = PAGE + 36 + 216 * index
            record = bytearray(original[position:position + 216])
            name = record[:196].split(b'\0')[0].decode('ascii')
            page, size, crc = struct.unpack_from('>III', record, 204)
            payload = original[page * PAGE:page * PAGE + size]
            assert zlib.crc32(payload) == crc
            entry = bank['entries'][index]
            assert entry['theme'] == name and entry['compressed_SHA256'] == sha(payload)
            if name in TARGETS:
                raw = zlib.decompress(payload[4:])
                modified, change = append_selector(raw, donor)
                payload = struct.pack('>I', len(modified)) + zlib.compress(modified, 9)
                assert zlib.decompress(payload[4:]) == modified
                change.update(theme=name, physical_code=entry['physical_code'])
                changed.append(change)
                entry.update(compressed_payload_unchanged=False, compressed_SHA256=sha(payload),
                             expanded_SHA256=sha(modified), menu_window_experiment=change)
            struct.pack_into('>III', record, 204, cursor, len(payload), zlib.crc32(payload))
            prefix[position:position + 216] = record
            padded = payload + b'\xff' * (-len(payload) % PAGE)
            payloads.extend(padded)
            cursor += len(padded) // PAGE
        result = bytes(prefix) + bytes(payloads)
        header_size = 36 + 216 * count
        assert len(result) <= SLOT_SIZE
        parse_candidate(result, header_size)
        target.write_bytes(result)
        hcrc = zlib.crc32(result[PAGE:PAGE + header_size])
        signed = struct.unpack('>i', struct.pack('>I', hcrc))[0]
        sidecar = Path(str(target) + '.inf')
        sidecar.write_bytes(seal_inf(sidecar.read_bytes(), result, {'HEADER_CRC32': signed}))
        bank.update(bytes=len(result), spare_bytes=SLOT_SIZE - len(result), SHA256=sha(result),
                    header_CRC32=f'{hcrc:08x}')
    assert {r['theme'] for r in changed} == TARGETS and len(changed) == 5
    revised['scope'] = 'EXPERIMENT: five missing MENU255/68 windows appended from Square; existing shared resources untouched and cross-theme dependencies UNVERIFIED'
    revised['asset_candidate_only'] = True
    revised['physical_car_approved'] = False
    revised['native_installation_tested'] = False
    revised['native_theme_activation_tested'] = False
    revised['source_asset_manifest'] = str((source / 'manifest.json').relative_to(ROOT))
    revised['source_asset_manifest_sha256'] = sha((source / 'manifest.json').read_bytes())
    revised['menu_window_experiment'] = {'donor': 'SQUARE NAV native255/68', 'changes': changed,
        'dependency_assumption': 'Test whether existing theme-local IDs/mappings can satisfy Square selector. No compatibility assertion; inspect private native UI/logs.',
        'new_native_menu_and_Internet_verification_required_for_all8': True,
        'no_guest_RAM_patch': True, 'no_SQL_changes_by_asset_script': True}
    revised['files'] = [{'path': str(p.relative_to(out / 'overlay')), 'bytes': p.stat().st_size,
                         'SHA256': sha(p.read_bytes())} for p in sorted((out / 'overlay').rglob('*')) if p.is_file()]
    assert len(revised['files']) == 12
    for item in manifest['files']:
        assert sha((source / 'overlay' / item['path']).read_bytes()) == item['SHA256']
    (out / 'manifest.json').write_text(json.dumps(revised, indent=2) + '\n')
    print(json.dumps({'assets': str(out.relative_to(ROOT)), 'menu_windows_appended': len(changed),
                      'shared_dependency_compatibility_verified': False, 'physical_car_approved': False}))


if __name__ == '__main__':
    main()
