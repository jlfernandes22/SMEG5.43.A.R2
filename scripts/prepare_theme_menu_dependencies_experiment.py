#!/usr/bin/env python3
"""Artifact-only MENU dependency relocation experiment; never install on hardware.

Native direct resource IDs are relocated only inside the transplanted selector.
All original windows and resource IDs remain intact. Existing binary pools are
retained byte-exact except the relocated image directory offsets; original image
payload bytes are retained once. Runtime verification remains mandatory.
"""
import json
from pathlib import Path
import struct
import sys
import zlib
import prepare_theme_menu_experiment as experiment

ROOT = experiment.ROOT
DONOR_RAW = None


def u32(data, offset=0):
    return struct.unpack_from('>I', data, offset)[0]


def pool(raw, index):
    size, offset = struct.unpack_from('>II', raw, index * 4)
    return raw[offset:offset + size]


def image_records(data):
    count, start = struct.unpack_from('>II', data, 4)
    assert start == 4 + count * 32 and count > 1
    records = [bytearray(data[16 + i * 32:48 + i * 32]) for i in range(count - 1)]
    assert all(len(r) == 32 for r in records)
    assert all(u32(r, 4) >= start and u32(r, 4) + u32(r, 8) <= len(data) for r in records if u32(r, 8))
    return count, start, records


def add_images(old, donor, ids):
    count, start, records = image_records(old)
    _, donor_start, donor_records = image_records(donor)
    donor_by_id = {u32(r): r for r in donor_records}
    next_id = max(u32(r) for r in records) + 1
    mapping = {id_: next_id + i for i, id_ in enumerate(sorted(ids))}
    delta = len(mapping) * 32
    new_start = start + delta
    payload = bytearray(old[start:])
    old_payload_hash = experiment.sha(payload)
    for record in records:
        if u32(record, 4) >= start:
            struct.pack_into('>I', record, 4, u32(record, 4) + delta)
    for donor_id, new_id in mapping.items():
        record = bytearray(donor_by_id[donor_id])
        offset, length = struct.unpack_from('>II', record, 4)
        assert offset >= donor_start and length > 0
        struct.pack_into('>II', record, 0, new_id, new_start + len(payload))
        payload.extend(donor[offset:offset + length])
        records.append(record)
    # Native writer stores count=real records+1 and firstData=4+count*32.
    # The final sentinel's last12 bytes intentionally overlap first pixel data.
    sentinel = old[16 + (count - 1) * 32:start]
    assert len(sentinel) == 20
    header = bytearray(old[:16])
    total = new_start + len(payload)
    struct.pack_into('>III', header, 0, total, count + len(mapping), new_start)
    result = bytes(header) + b''.join(records) + sentinel + bytes(payload)
    assert len(result) == total
    assert result[new_start:new_start + len(old) - start] == old[start:]
    return result, mapping, {'original_pixel_payload_SHA256': old_payload_hash,
                            'original_pixel_payload_preserved': True,
                            'donor_image_ids': sorted(ids), 'appended_image_count': len(mapping)}


def add_colors(old, donor, ids):
    assert len(old) == 8 + u32(old, 4) * 8 and len(donor) == 8 + u32(donor, 4) * 8
    source = dict(struct.iter_unpack('>II', donor[8:]))
    next_id = max(i for i, _ in struct.iter_unpack('>II', old[8:])) + 1
    mapping = {id_: next_id + n for n, id_ in enumerate(sorted(ids))}
    result = bytearray(old)
    for id_, target in mapping.items():
        result.extend(struct.pack('>II', target, source[id_]))
    struct.pack_into('>II', result, 0, len(result), u32(old, 4) + len(mapping))
    assert result[8:len(old)] == old[8:]
    return bytes(result), mapping


def font_data(data):
    count, base, nfamilies = struct.unpack_from('>III', data, 4)
    assert base == 16 + count * 28
    records = [data[16 + i * 28:44 + i * 28] for i in range(count)]
    families = {}
    for i in range(nfamilies):
        key, offset, size = struct.unpack_from('>III', data, base + i * 12)
        assert offset + size <= len(data) and size % 2 == 0
        families[key] = data[offset:offset + size]
    return records, families


def add_fonts(old, donor, ids):
    records, families = font_data(old)
    source_records, source_families = font_data(donor)
    source = {u32(r): r for r in source_records}
    next_id = max(u32(r) for r in records) + 1
    mapping = {id_: next_id + n for n, id_ in enumerate(sorted(ids))}
    original_records = list(records)
    for id_, target in mapping.items():
        record = bytearray(source[id_])
        family_bytes = source_families[u32(record, 4)]
        family_id = next((i for i, value in families.items() if value == family_bytes), None)
        if family_id is None:
            family_id = max(families, default=-1) + 1
            families[family_id] = family_bytes
        struct.pack_into('>II', record, 0, target, family_id)
        records.append(bytes(record))
    base = 16 + len(records) * 28
    cursor = base + 12 * len(families)
    directory, payload = bytearray(), bytearray()
    for key, value in sorted(families.items()):
        directory.extend(struct.pack('>III', key, cursor, len(value)))
        payload.extend(value)
        cursor += len(value)
    result = struct.pack('>IIII', cursor, len(records), base, len(families)) + b''.join(records) + directory + payload
    assert font_data(result)[0][:len(original_records)] == original_records
    assert all(font_data(result)[1][key] == value for key, value in font_data(old)[1].items())
    return bytes(result), mapping


def append_selector(raw, donor_window):
    assert DONOR_RAW is not None
    base, windows = experiment.windows(raw)
    target = windows[255, 68]
    assert len(target['bytes']) == 608
    donor = bytearray(donor_window)
    wanted = {33: set(), 25: set(), 13: set()}
    for position in range(0, len(donor), 16):
        tag, children, kind, value = struct.unpack_from('>4I', donor, position)
        if children == 0 and tag in wanted:
            assert kind == 0
            wanted[tag].add(value)
    images, imap, image_audit = add_images(pool(raw, 21), pool(DONOR_RAW, 21), wanted[33])
    fonts, fmap = add_fonts(pool(raw, 11), pool(DONOR_RAW, 11), wanted[25])
    colors, cmap = add_colors(pool(raw, 9), pool(DONOR_RAW, 9), wanted[13])
    maps = {33: imap, 25: fmap, 13: cmap}
    changed_leaves = []
    for position in range(0, len(donor), 16):
        tag, children, kind, value = struct.unpack_from('>4I', donor, position)
        if children == 0 and tag in maps:
            struct.pack_into('>I', donor, position + 12, maps[tag][value])
            changed_leaves.append({'window_offset': position + 12, 'tag': tag, 'old': value, 'new': maps[tag][value]})
    assert struct.unpack_from('>4I', donor, 0x40) == (20, 0, 1, 1)
    struct.pack_into('>I', donor, 0x4c, 0)
    image_offset = u32(raw, 22 * 4)
    assert image_offset + len(pool(raw, 21)) == len(raw)
    result = bytearray(raw[:image_offset])
    for index, data in [(9, colors), (11, fonts)]:
        result.extend(b'\0' * (-len(result) % 4))
        offset = len(result)
        result.extend(data)
        struct.pack_into('>II', result, index * 4, len(data), offset)
    result.extend(b'\0' * (-len(result) % 16))
    window_offset = len(result)
    result.extend(donor)
    result.extend(b'\0' * (-len(result) % 4))
    new_image_offset = len(result)
    result.extend(images)
    struct.pack_into('>II', result, 21 * 4, len(images), new_image_offset)
    directory_word = 0x6c + target['directory_index'] * 16 + 8
    struct.pack_into('>I', result, directory_word, window_offset - base)
    struct.pack_into('>I', result, 0, len(result))
    assert all(bytes(result[row['start']:row['start'] + len(row['bytes'])]) == row['bytes']
               for key, row in windows.items() if key != (255, 68))
    assert bytes(result[window_offset:window_offset + len(donor)]) == donor
    assert pool(result, 21) == images
    return bytes(result), {'old_window_bytes': 608, 'new_window_bytes': len(donor),
        'old_window_sha256': experiment.sha(target['bytes']), 'new_window_sha256': experiment.sha(donor),
        'old_expanded_bytes': len(raw), 'new_expanded_bytes': len(result),
        'all_other_windows_original_bytes_preserved': True, 'original_resource_IDs_preserved': True,
        'original_fonts_and_colors_preserved': True, 'image_pool': image_audit,
        'direct_ID_maps': {str(tag): values for tag, values in maps.items()},
        'relocated_window_leaves': changed_leaves, 'root_enableAnimations': 0,
        'existing_global_animations_unchanged': True, 'runtime_dependency_compatibility_verified': False}


def main():
    global DONOR_RAW
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--assets', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = args.assets.resolve()
    data = (source / 'overlay/HARMONY/BigHarmony_4/BIG_HARMONY.bin').read_bytes()
    position = experiment.PAGE + 36
    page, size = struct.unpack_from('>II', data, position + 204)
    DONOR_RAW = zlib.decompress(data[page * experiment.PAGE + 4:page * experiment.PAGE + size])
    assert experiment.sha(DONOR_RAW) == 'de7f758f7b69a3303214d048df7bb1ea41c6a2d49679a70bbfb14495122b2007'
    experiment.append_selector = append_selector
    experiment.main()
    manifest_path = args.output.resolve() / 'manifest.json'
    manifest = json.loads(manifest_path.read_text())
    manifest['scope'] = 'EXPERIMENT: Square native MENU direct image/font/color dependencies relocated privately in five old themes; MENU root animations disabled. All other windows and original resource IDs preserved. Runtime compatibility unverified.'
    manifest['menu_window_experiment']['dependency_assumption'] = 'Direct image/font/color IDs relocated using native pool schemas; root animation disabled. Requires native menu and Internet verification; no physical approval.'
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')

if __name__ == '__main__':
    main()
