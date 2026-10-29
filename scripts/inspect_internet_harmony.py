#!/usr/bin/env python3
"""Inspect native window directories; optionally build a QEMU-only resource control.

The control replaces one compressed SQUARE resource, preserving Audio bank
selection, its directory metadata, NAND geometry/OOB and all database sectors.
It is an emulator experiment, not a USB or physical firmware update package.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import zlib

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / 'artifacts/phase2/package/SMEG_PLUS_UPG/HARMONY'
PAGE, STRIDE, AUDIO_SLOT, SLOT_SIZE = 2048, 2112, 0x2dc0000, 0x21a0000


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def bank(group):
    source = PACKAGE / f'BigHarmony_{group}/BIG_HARMONY.bin'
    data = source.read_bytes()
    values = dict(line.split(':', 1) for line in source.with_name(source.name + '.inf').read_text().replace('\\n', '\n').splitlines() if ':' in line)
    header_size = int(values['HEADER_SIZE'])
    assert zlib.crc32(data[PAGE:PAGE + header_size]) == int(values['HEADER_CRC32']) & 0xffffffff
    result = []
    for i in range(struct.unpack_from('>I', data, 0x820)[0]):
        record = data[0x824 + 216*i:0x824 + 216*(i+1)]
        page, size, crc = struct.unpack_from('>III', record, 0xcc)
        payload = data[page*PAGE:page*PAGE + size]
        assert zlib.crc32(payload) == crc
        raw = zlib.decompress(payload[4:])
        assert len(raw) == struct.unpack_from('>I', payload)[0]
        count, base = struct.unpack_from('>II', raw, 4)
        assert 0x6c + 16*count <= len(raw)
        windows = [struct.unpack_from('>4I', raw, 0x6c + j*16) for j in range(count)]
        assert all(base + w[2] < len(raw) for w in windows)
        result.append({'group': group, 'theme': record[:196].split(b'\0')[0].decode(),
                       'source_sha256': sha(source), 'compressed_crc32_verified': f'{crc:08x}',
                       'window_count': count, 'expanded_bytes': len(raw),
                       'internet_windows': [list(w) for w in windows if w[0] == 8],
                       '_payload': payload})
    return data, values, result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--control-seed', type=Path)
    ap.add_argument('--control-nand', type=Path)
    a = ap.parse_args()
    if bool(a.control_seed) != bool(a.control_nand): ap.error('Both control paths required')
    report = {'physical_device_access': False, 'emulator_only': True, 'banks': []}
    parsed = {}
    for group in (2, 3, 4, 5):
        parsed[group] = bank(group)
        report['banks'] += [{k:v for k,v in row.items() if not k.startswith('_')} for row in parsed[group][2]]
    nav_ids = {w[1] for w in parsed[3][2][0]['internet_windows']}
    audio_ids = {w[1] for w in parsed[4][2][0]['internet_windows']}
    report['Audio_missing_NAV_Internet_windows'] = sorted(nav_ids - audio_ids)
    report['native_secondary_menu_request'] = {'application': 8, 'screen': 3, 'Audio_present': 3 in audio_ids, 'NAV_present': 3 in nav_ids}
    if a.control_seed:
        src, dst = a.control_seed.resolve(), a.control_nand.resolve()
        assert src.is_relative_to(ROOT/'artifacts') and dst.is_relative_to(ROOT/'artifacts/phase12')
        assert src.is_file() and not dst.exists() and src.stat().st_size == 512*1024**2//PAGE*STRIDE
        before_sha = sha(src)
        audio, values, rows = parsed[4]
        assert len(rows) == 1 and rows[0]['theme'] == parsed[3][2][0]['theme'] == 'SQUARE'
        nav_payload = parsed[3][2][0]['_payload']
        prefix = bytearray(audio[:2*PAGE])
        struct.pack_into('>III', prefix, 0x824 + 0xcc, 2, len(nav_payload), zlib.crc32(nav_payload))
        header_size = int(values['HEADER_SIZE'])
        crc = zlib.crc32(prefix[PAGE:PAGE+header_size])
        with src.open('rb') as f:
            f.seek(AUDIO_SLOT//PAGE*STRIDE)
            preheader = bytearray(f.read(PAGE))
        assert preheader.startswith(b'BIGHARMONY')
        assert struct.unpack_from('>II', preheader, 0xa0) == (header_size, int(values['HEADER_CRC32']) & 0xffffffff)
        struct.pack_into('>I', preheader, 0xa4, crc)
        replacement = bytes(preheader) + bytes(prefix[PAGE:]) + nav_payload
        replacement += b'\xff' * (-len(replacement) % PAGE)
        assert len(replacement) < SLOT_SIZE
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        with dst.open('r+b') as f:
            for off in range(0, len(replacement), PAGE):
                f.seek((AUDIO_SLOT+off)//PAGE*STRIDE)
                f.write(replacement[off:off+PAGE])
        changed = 0
        with src.open('rb') as f, dst.open('rb') as g:
            for page, original in enumerate(iter(lambda:f.read(STRIDE), b'')):
                modified = g.read(STRIDE)
                assert original[PAGE:] == modified[PAGE:]
                if original != modified:
                    assert AUDIO_SLOT <= page*PAGE < AUDIO_SLOT+len(replacement)
                    changed += 1
        assert sha(src) == before_sha
        report['resource_control'] = {'input':str(src), 'input_sha256':before_sha,
            'output':str(dst), 'output_sha256':sha(dst), 'changed_pages':changed,
            'all_OOB_and_other_sectors_preserved':True, 'saved_preferences_changed':False,
            'selected_theme':'SQUARE; original Audio bank101 retained',
            'borrowed_resource':'Original NAV SQUARE whole compiled resource; includes other NAV layouts, so not a minimal production patch',
            'physical_update_package':False}
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'report':str(a.output), 'Audio_missing_Internet_windows':report['Audio_missing_NAV_Internet_windows'], 'control':str(a.control_nand)}))


if __name__ == '__main__': main()
