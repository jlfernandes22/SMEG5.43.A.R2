#!/usr/bin/env python3
"""Create a NEW artifact-only ESSENTIEL Color-schemes geometry experiment.

Only four BE32 scalar values inside app22/window0 are changed. Other widgets,
field/event bindings, theme graphics, binary code and SQL remain unchanged.
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


def sha(data):
    return hashlib.sha256(data).hexdigest()


def modify(raw):
    raw = bytes(raw)
    count, base = struct.unpack_from('>II', raw, 4)
    matches = [struct.unpack_from('>4I', raw, 0x6c + 16 * i) for i in range(count)
               if struct.unpack_from('>II', raw, 0x6c + 16 * i) == (22, 0)]
    assert len(matches) == 1
    start = base + matches[0][2]
    assert struct.unpack_from('>I', raw, start)[0] == 88
    size = 16 * (struct.unpack_from('>I', raw, start + 12)[0] + 1)
    window = raw[start:start + size]
    proposal = json.loads((ROOT / 'artifacts/phase15/theme-analysis/ESSENTIEL-color-geometry-proposal.json').read_text())
    assert sha(window) == proposal['window_SHA256'] and size == 7584
    result = bytearray(raw)
    changes = []
    permitted = set()
    for item in proposal['proposed_changes']:
        offset = start + item['window_offset']
        assert struct.unpack_from('>I', result, offset)[0] == item['expected']
        struct.pack_into('>I', result, offset, item['proposed'])
        changes.append(dict(item, expanded_offset=offset))
        permitted.update(range(offset, offset + 4))
    assert len(changes) == 4
    assert all(a == b or i in permitted for i, (a, b) in enumerate(zip(raw, result)))
    assert len(result) == len(raw)
    return bytes(result), {'application': 22, 'window': 0, 'old_window_SHA256': sha(window),
        'new_window_SHA256': sha(result[start:start + size]), 'changes': changes,
        'all_other_expanded_bytes_preserved': True, 'native_field_and_event_3500_preserved': True,
        'all_other_windows_preserved': True, 'runtime_visual_and_click_verification': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assets', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source, out = args.assets.resolve(), args.output.resolve()
    allowed = ROOT / 'artifacts/phase15/theme-assets'
    assert source.is_relative_to(allowed) and out.is_relative_to(allowed) and not out.exists()
    source_manifest = (source / 'manifest.json').read_bytes()
    assert sha(source_manifest) == 'ec25bac46522c65c6a18bb6860898f4ac9e3bb1673a2748a3e5ec2c05d1ba3a5'
    manifest = json.loads(source_manifest)
    assert len(manifest['files']) == 12
    for item in manifest['files']:
        path = source / 'overlay' / item['path']
        assert not path.is_symlink() and path.is_file()
        assert path.stat().st_size == item['bytes'] and sha(path.read_bytes()) == item['SHA256']
    out.mkdir(parents=True)
    shutil.copytree(source / 'overlay', out / 'overlay')
    revised = copy.deepcopy(manifest)
    modified_count = 0
    for bank in revised['banks']:
        if not any(e['theme'] == 'ESSENTIEL' for e in bank['entries']):
            continue
        target = out / 'overlay/HARMONY' / ('BigHarmony_' + str(bank['target_group'])) / 'BIG_HARMONY.bin'
        original = target.read_bytes()
        count = struct.unpack_from('>I', original, PAGE + 32)[0]
        prefix, payloads, cursor = bytearray(original[:2 * PAGE]), bytearray(), 2
        for index, entry in enumerate(bank['entries']):
            position = PAGE + 36 + 216 * index
            record = bytearray(original[position:position + 216])
            page, size, crc = struct.unpack_from('>III', record, 204)
            payload = original[page * PAGE:page * PAGE + size]
            assert sha(payload) == entry['compressed_SHA256'] and zlib.crc32(payload) == crc
            if entry['theme'] == 'ESSENTIEL':
                raw = zlib.decompress(payload[4:])
                new_raw, audit = modify(raw)
                payload = struct.pack('>I', len(new_raw)) + zlib.compress(new_raw, 9)
                assert zlib.decompress(payload[4:]) == new_raw
                entry.update(compressed_SHA256=sha(payload), expanded_SHA256=sha(new_raw),
                             color_geometry_experiment=audit)
                modified_count += 1
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
        bank.update(bytes=len(result), spare_bytes=SLOT_SIZE - len(result), SHA256=sha(result), header_CRC32=f'{hcrc:08x}')
    assert modified_count == 1
    revised.update(scope=manifest['scope'] + ' Additional ESSENTIEL22/0 four-scalar Color button geometry experiment.',
        source_asset_manifest=str((source / 'manifest.json').relative_to(ROOT)),
        source_asset_manifest_sha256=sha(source_manifest), physical_car_approved=False,
        color_geometry_experiment={'theme': 'ESSENTIEL', 'only_four_window_scalar_values_changed': True,
                                   'native_visual_and_click_verification_required': True})
    revised['files'] = [{'path': str(p.relative_to(out / 'overlay')), 'bytes': p.stat().st_size,
                         'SHA256': sha(p.read_bytes())} for p in sorted((out / 'overlay').rglob('*')) if p.is_file()]
    assert len(revised['files']) == 12
    for item in manifest['files']:
        assert sha((source / 'overlay' / item['path']).read_bytes()) == item['SHA256']
    (out / 'manifest.json').write_text(json.dumps(revised, indent=2) + '\n')
    print(json.dumps({'assets': str(out.relative_to(ROOT)), 'changed_window_scalar_values': 4,
                      'physical_car_approved': False}))

if __name__ == '__main__':
    main()
