#!/usr/bin/env python3
"""Restore ESSENTIEL's native Colour button using its own tile and font style.

Creates new artifact files only. No firmware code, SQL, existing image, or
physical media is modified. Native click/display verification is mandatory.
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


def parse(data, offset=0):
    tag, count, kind, value = struct.unpack_from('>4I', data, offset)
    node = {'tag': tag, 'kind': kind, 'value': value, 'children': []}
    end = offset + 16
    for _ in range(count):
        child, end = parse(data, end)
        node['children'].append(child)
    if count:
        assert end - offset == 16 * (value + 1)
    return node, end


def encode(node):
    children = b''.join(encode(child) for child in node['children'])
    value = len(children) // 16 if node['children'] else node['value']
    return struct.pack('>4I', node['tag'], len(node['children']), node['kind'], value) + children


def modify(raw, label_y=111):
    count, base = struct.unpack_from('>II', raw, 4)
    matches = [(i, struct.unpack_from('>4I', raw, 0x6c + 16 * i)) for i in range(count)
               if struct.unpack_from('>II', raw, 0x6c + 16 * i) == (22, 0)]
    assert len(matches) == 1
    index, row = matches[0]
    start = base + row[2]
    tree, end = parse(raw, start)
    old = raw[start:end]
    assert encode(tree) == old and len(old) == 7584
    # Source-proven hierarchy: window/widgets/parent(94,142)/widgets.
    widgets = next(c for c in tree['children'] if c['tag'] == 86)
    parent = widgets['children'][1]
    group = next(c for c in parent['children'] if c['tag'] == 86)
    audio, colour, sleep = group['children']
    assert all(c['tag'] == 85 for c in (audio, colour, sleep))
    props = lambda n: {c['tag']: c for c in n['children']}
    ap, cp = props(audio), props(colour)
    assert ap[76]['value'] == 1584 and cp[76]['value'] == 1583
    assert (cp[56]['value'], cp[57]['value'], cp[87]['value'], cp[28]['value']) == (409, 21, 194, 94)
    # Preserve Colour's native field/event subtrees and localized caption.
    before_binding = [encode(c) for c in colour['children'] if c['tag'] not in (38,)]
    background = copy.deepcopy(ap[6])
    label = copy.deepcopy(ap[38])
    normal = next(c for c in label['children'] if c['tag'] == 49)
    normal_props = props(normal)
    assert normal_props[57]['value'] == 111
    # ESSENTIEL's white caption belongs below its white tile, as on Audio.
    # y15 is retained only as a reproducible failed diagnostic experiment.
    assert label_y in (15, 111)
    normal_props[57]['value'] = label_y
    colour['children'] = [c for c in colour['children'] if c['tag'] != 38]
    text_index = next(i for i, c in enumerate(colour['children']) if c['tag'] == 76)
    colour['children'].insert(text_index, background)
    colour['children'].insert(text_index + 2, label)
    assert [encode(c) for c in colour['children'] if c['tag'] not in (6, 38)] == before_binding
    new = encode(tree)
    rebuilt, consumed = parse(new)
    assert consumed == len(new) and encode(rebuilt) == new
    target = (len(raw) + 15) & ~15
    result = bytearray(raw + b'\0' * (target - len(raw)) + new)
    directory_field = 0x6c + index * 16 + 8
    struct.pack_into('>I', result, 0, len(result))
    struct.pack_into('>I', result, directory_field, target - base)
    permitted = set(range(4)) | set(range(directory_field, directory_field + 4))
    assert all(a == b or i in permitted for i, (a, b) in enumerate(zip(raw, result)))
    return bytes(result), {
        'application': 22, 'window': 0, 'old_window_sha256': sha(old), 'new_window_sha256': sha(new),
        'old_window_bytes': len(old), 'new_window_bytes': len(new),
        'appended_window_offset': target, 'directory_field': directory_field,
        'native_Colour_caption_1583_and_field_event_3500_preserved': True,
        'background_and_font_source': 'same ESSENTIEL window native Audio tile',
        'label_y': label_y, 'audio_icon_not_copied': True, 'animations_not_added': True,
        'all_existing_shared_resources_and_other_window_bytes_preserved': True,
        'visual_and_native_click_verified': False,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--assets', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--label-y', type=int, choices=(15, 111), default=111)
    a = p.parse_args()
    source, out = a.assets.resolve(), a.output.resolve()
    allowed = ROOT / 'artifacts/phase15/theme-assets'
    assert source.is_relative_to(allowed) and out.is_relative_to(allowed) and not out.exists()
    manifest_bytes = (source / 'manifest.json').read_bytes()
    manifest = json.loads(manifest_bytes)
    assert len(manifest['files']) == 12
    for item in manifest['files']:
        path = source / 'overlay' / item['path']
        assert path.is_file() and not path.is_symlink()
        assert path.stat().st_size == item['bytes'] and sha(path.read_bytes()) == item['SHA256']
    out.mkdir(parents=True)
    shutil.copytree(source / 'overlay', out / 'overlay')
    revised = copy.deepcopy(manifest)
    changes = []
    for bank in revised['banks']:
        if not any(e['theme'] == 'ESSENTIEL' for e in bank['entries']):
            continue
        target = out / 'overlay/HARMONY' / ('BigHarmony_' + str(bank['target_group'])) / 'BIG_HARMONY.bin'
        old = target.read_bytes()
        prefix, payloads, cursor = bytearray(old[:2 * PAGE]), bytearray(), 2
        count = struct.unpack_from('>I', old, PAGE + 32)[0]
        for i, entry in enumerate(bank['entries']):
            position = PAGE + 36 + 216 * i
            record = bytearray(old[position:position + 216])
            page, size, crc = struct.unpack_from('>III', record, 204)
            payload = old[page * PAGE:page * PAGE + size]
            assert zlib.crc32(payload) == crc and sha(payload) == entry['compressed_SHA256']
            if entry['theme'] == 'ESSENTIEL':
                raw, audit = modify(zlib.decompress(payload[4:]), a.label_y)
                payload = struct.pack('>I', len(raw)) + zlib.compress(raw, 9)
                assert zlib.decompress(payload[4:]) == raw
                entry.update(compressed_SHA256=sha(payload), expanded_SHA256=sha(raw), colour_style_restoration=audit)
                changes.append(audit)
            struct.pack_into('>III', record, 204, cursor, len(payload), zlib.crc32(payload))
            prefix[position:position + 216] = record
            padded = payload + b'\xff' * (-len(payload) % PAGE)
            payloads.extend(padded)
            cursor += len(padded) // PAGE
        result = bytes(prefix) + bytes(payloads)
        assert len(result) <= SLOT_SIZE
        parse_candidate(result, 36 + 216 * count)
        target.write_bytes(result)
        hcrc = zlib.crc32(result[PAGE:PAGE + 36 + 216 * count])
        signed = struct.unpack('>i', struct.pack('>I', hcrc))[0]
        sidecar = Path(str(target) + '.inf')
        sidecar.write_bytes(seal_inf(sidecar.read_bytes(), result, {'HEADER_CRC32': signed}))
        bank.update(bytes=len(result), spare_bytes=SLOT_SIZE-len(result), SHA256=sha(result), header_CRC32=f'{hcrc:08x}')
    assert len(changes) == 1
    revised.update(scope=manifest['scope'] + ' ESSENTIEL Colour tile native style restored.',
        source_asset_manifest=str((source / 'manifest.json').relative_to(ROOT)),
        source_asset_manifest_sha256=sha(manifest_bytes), physical_car_approved=False,
        colour_style_restoration=changes[0])
    revised['files'] = [{'path': str(p.relative_to(out / 'overlay')), 'bytes': p.stat().st_size, 'SHA256': sha(p.read_bytes())}
                        for p in sorted((out / 'overlay').rglob('*')) if p.is_file()]
    assert len(revised['files']) == 12
    (out / 'manifest.json').write_text(json.dumps(revised, indent=2) + '\n')
    print(json.dumps({'assets': str(out.relative_to(ROOT)), 'manifest_sha256': sha((out / 'manifest.json').read_bytes()),
                      'changed_windows': 1, 'physical_car_approved': False}))


if __name__ == '__main__':
    main()
