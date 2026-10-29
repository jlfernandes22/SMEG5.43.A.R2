#!/usr/bin/env python3
"""Create fingerprint-guarded AUDIO_BT_256 disk candidates for QEMU only.

The complete two-stream BigQuick container is retained. This does not generate
a USB package, authenticate an update, install firmware, or access a device.
The two bytes after each zlib stream are the native one's-complement checksum.
Their interpretation is verified against all six original firmware streams.
"""
import argparse
import array
import hashlib
import json
import struct
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_ROOT = (ROOT / 'artifacts/phase13').resolve()
SOURCE = ROOT / 'artifacts/phase2/package/SMEG_PLUS_UPG/AUDIO_BT_256/AppBin/f_BigQuick.bin'
SOURCE_SHA = 'c3f329c0d56c4a1726b097ccd55a0eaf44f6ece0a14018886d146b09e47ccfa2'
SEGMENTS = [
    ('app.bin', 0x01000000, '2ff81057b66d02daa9c4b9687f5407396425f81555b80d02feb6672aebb89925'),
    ('app_segment2.bin', 0x04c00000, '03537bef77bbc54c64003159a0bcd3c5770b216a0290f89ac3415ab974f714b8'),
]
ELIGIBILITY = [
    (0, 0x0227f7b4, '409e0010', '60000000', 'Desktop conditional INT_E rejection -> nop'),
    (1, 0x04c171bc, '7c630034', '38600020', 'Backend RAM-profile inversion -> li r3,32; following srwi yields1'),
]
AGENDA = [
    (0, 0x0182d1e0, '981d00ba', '997d00ba', 'Agenda C1: initialize m_force_no_dun_management with verified zero r11'),
    (0, 0x0182d4b8, '981d00ba', '997d00ba', 'Agenda C2: initialize m_force_no_dun_management with verified zero r11'),
]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def digest(data):
    return {'bytes': len(data), 'sha256': sha(data), 'crc32': f'{zlib.crc32(data):08x}'}


def native_cksum(data):
    """Aligned fresh native cksum(0, data, length), including an odd trailing byte."""
    words = array.array('H', data + (b'\0' if len(data) & 1 else b''))
    if sys.byteorder == 'little':
        words.byteswap()
    value = sum(words)
    while value > 0xffff:
        value = (value & 0xffff) + (value >> 16)
    return value


def checksum_suffix(body):
    # An odd byte count puts the checksum itself on an odd byte boundary.
    return (0xffff ^ native_cksum(body)).to_bytes(2, 'little' if len(body) & 1 else 'big')


def parse(raw):
    assert struct.unpack_from('>I', raw)[0] == 0x10004
    assert all(struct.unpack_from('>8I', raw, n * 32) == (0xdeadbeef,) * 8 for n in range(2, 64))
    positions = [0x800, (struct.unpack_from('>I', raw, 0x20)[0] + 1) * 2048]
    result = []
    for index, marker in enumerate(positions):
        fields = struct.unpack_from('>8I', raw, index * 32)
        assert sum(fields[1:6]) & 0xffffffff == fields[6], 'Invalid native header arithmetic check'
        assert raw[marker] == 8
        decoder = zlib.decompressobj()
        image = decoder.decompress(raw[marker + 1:], 128 * 1024 * 1024)
        assert decoder.eof and not decoder.unconsumed_tail
        end = len(raw) - len(decoder.unused_data)
        assert len(image) == struct.unpack_from('>I', raw, 32 * index + 4)[0]
        assert end - marker + 2 == struct.unpack_from('>I', raw, 32 * index + 20)[0]
        suffix = raw[end:end + 2]
        assert len(suffix) == 2
        assert suffix == checksum_suffix(raw[marker:end])
        assert native_cksum(raw[marker:end + 2]) == 0xffff
        result.append({'image': image, 'marker': marker, 'zlib_end': end, 'suffix': suffix})
    assert set(raw[result[0]['zlib_end'] + 2:positions[1]]) == {0xee}
    assert result[1]['zlib_end'] + 2 == len(raw)
    return result


def make_candidate(raw, parts, patches):
    images = [bytearray(part['image']) for part in parts]
    changes = []
    for index, address, old, new, reason in patches:
        offset = address - SEGMENTS[index][1]
        before, after = bytes.fromhex(old), bytes.fromhex(new)
        assert bytes(images[index][offset:offset + 4]) == before
        if address in (0x0182d1e0, 0x0182d4b8):
            # r11=0, r0=1, neither modified before the field store.
            assert bytes(images[index][offset - 16:offset]) == bytes.fromhex('39600000939d00b4380000013929b580')
        images[index][offset:offset + 4] = after
        changes.append({'segment': index, 'runtime_address': f'0x{address:08x}',
                        'decompressed_file_offset': f'0x{offset:x}',
                        'expected': old, 'replacement': new, 'reason': reason})
    # The user-supplied address is not the field assignment. Preserve it.
    supplied = 0x0182d338 - SEGMENTS[0][1]
    assert images[0][supplied:supplied + 4] == parts[0]['image'][supplied:supplied + 4] == bytes.fromhex('3d200183')
    allowed = [{i for patch in changes if patch['segment'] == index
                for i in range(int(patch['decompressed_file_offset'], 16), int(patch['decompressed_file_offset'], 16) + 4)}
               for index in range(2)]
    for index in range(2):
        actual = {i for i, (old, new) in enumerate(zip(parts[index]['image'], images[index])) if old != new}
        assert actual <= allowed[index]
    header = bytearray(raw[:0x800])
    bodies = [b'\x08' + zlib.compress(bytes(image), 9) for image in images]
    streams = [body + checksum_suffix(body) for body in bodies]
    second = parts[1]['marker']
    assert 0x800 + len(streams[0]) <= second
    for index, stream in enumerate(streams):
        struct.pack_into('>I', header, index * 32 + 20, len(stream))
        fields = struct.unpack_from('>8I', header, index * 32)
        struct.pack_into('>I', header, index * 32 + 24, sum(fields[1:6]) & 0xffffffff)
    candidate = bytes(header) + streams[0]
    candidate += b'\xee' * (second - len(candidate))
    candidate += streams[1]
    check = parse(candidate)
    assert [part['image'] for part in check] == [bytes(image) for image in images]
    assert all(check[i]['marker'] == parts[i]['marker'] for i in range(2))
    header_allowed = set(range(0x14, 0x1c)) | set(range(0x34, 0x3c))
    assert {i for i, pair in enumerate(zip(raw[:0x800], header)) if pair[0] != pair[1]} <= header_allowed
    return candidate, images, changes, check


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, default=OUTPUT_ROOT / 'binary-analysis')
    ap.add_argument('--variant', choices=['eligibility', 'eligibility-agenda', 'both'], default='both')
    args = ap.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(OUTPUT_ROOT) or output == OUTPUT_ROOT:
        raise SystemExit('Output must be a new directory inside artifacts/phase13')
    if output.exists():
        raise SystemExit('Refusing existing output directory')
    raw = SOURCE.read_bytes()
    assert sha(raw) == SOURCE_SHA, 'Wrong source firmware fingerprint'
    parts = parse(raw)
    for index, (filename, base, expected) in enumerate(SEGMENTS):
        assert sha(parts[index]['image']) == expected
        assert parts[index]['image'] == (ROOT / 'artifacts/phase2/applications/AUDIO_BT_256' / filename).read_bytes()
    output.mkdir(parents=True, exist_ok=False)
    report = {'emulator_only': True, 'physical_car_approved': False,
              'native_updater_applied': False, 'persistent_reboot_verified': False,
              'format_revision': 3,
              'source': str(SOURCE.relative_to(ROOT)), 'source_digest': digest(raw),
              'supplied_address_0x0182d338': {'bytes_unchanged': '3d200183',
                  'instruction': 'lis r9,0x183', 'is_boolean_assignment': False},
              'source_segments': [], 'variants': {},
              'limitations': [
                  'Native stream checksum and header arithmetic checks are verified; acceptance by the complete native installer remains untested.',
                  'Container round trip and exact instruction edits are verified, native installer acceptance is not.',
                  'Package metadata/checksum cascade and contract re-seal are separate work; this is not a flashable update.',
                  'Web_active remains an independent prerequisite; this script does not edit any database.',
                  'No Bluetooth context-menu conditional is modified, and no stored hardware identity is changed.',
                  'Agenda zero initializes a policy field, but cannot establish functioning PAN, DUN, IP, or browser services.',
                  'Existing tools/patch_smeg.py drops the second zlib stream when repacking; it must not be used unchanged for this candidate.',
              ]}
    for index, part in enumerate(parts):
        report['source_segments'].append({'index': index, 'file': SEGMENTS[index][0],
            'runtime_base': hex(SEGMENTS[index][1]), 'marker_offset': hex(part['marker']),
            'checksum_suffix_hex': part['suffix'].hex(),
            'native_cksum_residue': 'ffff', **digest(part['image'])})
    for name, patches in [('eligibility', ELIGIBILITY), ('eligibility-agenda', ELIGIBILITY + AGENDA)]:
        if args.variant != 'both' and args.variant != name:
            continue
        candidate, images, changes, checked = make_candidate(raw, parts, patches)
        destination = output / name
        destination.mkdir()
        (destination / 'f_BigQuick.bin').write_bytes(candidate)
        for index, image in enumerate(images):
            (destination / SEGMENTS[index][0]).write_bytes(image)
        entry = {'container': digest(candidate), 'patches': changes,
                 'all_other_decompressed_bytes_unchanged': True,
                 'second_segment_preserved': True, 'segments': []}
        for index, part in enumerate(checked):
            entry['segments'].append({'index': index, 'marker_offset': hex(part['marker']),
                'checksum_suffix_hex': part['suffix'].hex(),
                'native_cksum_residue': 'ffff', **digest(part['image'])})
        report['variants'][name] = entry
    assert sha(SOURCE.read_bytes()) == SOURCE_SHA
    (output / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'manifest': str(output / 'manifest.json'),
                      'variants': list(report['variants']), 'physical_car_approved': False}))


if __name__ == '__main__':
    main()
