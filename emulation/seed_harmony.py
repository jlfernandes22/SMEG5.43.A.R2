#!/usr/bin/env python3
"""Seed A9 NAV harmony payloads in an independent copy of formatted NAND.

Replays recovered native updater layout; preserves all OOB and all other pages.
Creates native HARMONY.INI separately for insertion into the SYSTEM_DATA FAT tree.
"""
import argparse
import hashlib
import json
import re
import shutil
import struct
import zlib
from pathlib import Path

PAGE, OOB, STRIDE, BLOCK = 2048, 64, 2112, 0x20000
SLOT_BASES = [0x39c0000, 0x4e00000, 0x6240000, 0x7680000, 0x8ac0000, 0x9f00000]
SLOT_BYTES = 0x1440000


def digest(data):
    return hashlib.sha256(data).hexdigest()


def filehash(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--input', required=True, type=Path)
    ap.add_argument('--output', required=True, type=Path)
    ap.add_argument('--package', type=Path, default=Path('artifacts/phase2/package/SMEG_PLUS_UPG'))
    ap.add_argument('--ini', type=Path, default=Path('artifacts/phase3/payloads/SYSTEM_DATA/HARMONY.INI'))
    ap.add_argument('--skin', type=int, default=101)
    ap.add_argument('--profile', choices=['nav512','audio256'], default='nav512')
    args = ap.parse_args()
    if args.output.exists() or args.input.resolve() == args.output.resolve():
        raise ValueError('output must be a new independent image')
    physical_size = args.input.stat().st_size
    geometries = {mib * 1024**2 // PAGE * STRIDE: mib for mib in (256, 512)}
    if physical_size not in geometries:
        raise ValueError('expected complete 256/512 MiB data NAND with 2048+64 page layout')
    nand_mib = geometries[physical_size]
    if nand_mib == 256 and args.profile != 'audio256':
        raise ValueError('256 MiB NAND requires the recovered Audio256 slot map')
    mapping_path = args.package / 'HARMONY/A9.bigharmony.ini'
    mapping_text = mapping_path.read_text().replace('\\n', '\n')
    slot_bases = [0x2dc0000,0x4f60000] if args.profile == 'audio256' else SLOT_BASES
    slot_bytes = 0x21a0000 if args.profile == 'audio256' else SLOT_BYTES
    list_name = 'LIST_AUDIO_BT' if args.profile == 'audio256' else 'LIST_NAV'
    match = re.search(r'^'+list_name+r':([0-9,]+)$', mapping_text, re.M)
    if not match:
        raise ValueError('A9 mapping absent for '+args.profile)
    mapping = [int(v) for v in match[1].split(',')]
    if len(mapping) != len(slot_bases):
        raise ValueError('Unexpected number of native harmony slots')
    plan = []
    for slot, group in enumerate(mapping):
        if not group:
            continue
        source = args.package / f'HARMONY/BigHarmony_{group}/BIG_HARMONY.bin'
        sidecar = source.with_name(source.name + '.inf')
        data = source.read_bytes()
        text = sidecar.read_text().replace('\\n', '\n')
        values = dict(line.split(':', 1) for line in text.splitlines() if ':' in line)
        header_size = int(values['HEADER_SIZE'])
        header_crc = int(values['HEADER_CRC32']) & 0xffffffff
        if zlib.crc32(data[PAGE:PAGE + header_size]) != header_crc:
            raise ValueError('original harmony internal header CRC mismatch')
        count = 1
        while slot + count < len(mapping) and mapping[slot + count] == 0:
            count += 1
        if len(data) > count * slot_bytes:
            raise ValueError('harmony source exceeds native allocated slot range')
        preheader = bytearray(0xa8)
        for offset, value in [(0, 'BIGHARMONY'), (0x20, '0.540.0'),
                              (0x40, values['VERSION_BIGHARMONY_STRUCT']),
                              (0x60, values['DATE']), (0x80, values['VERSION'])]:
            encoded = value.encode('ascii')
            if len(encoded) >= 32:
                raise ValueError('metadata string exceeds native field')
            preheader[offset:offset + len(encoded)] = encoded
        struct.pack_into('>II', preheader, 0xa0, header_size, header_crc)
        # Native WriteBigHarmony writes source starting at offset0x800 to page+1,
        # then writes its generated 0xA8-byte preheader to the first page.
        payload = bytes(preheader) + b'\xff' * (PAGE - len(preheader)) + data[PAGE:]
        if slot_bases[slot] + count * slot_bytes > nand_mib * 1024**2:
            raise ValueError('native harmony allocation exceeds complete NAND geometry')
        plan.append({'source': str(source), 'source_sha256': digest(data),
                     'sidecar': str(sidecar), 'sidecar_sha256': filehash(sidecar),
                     'slot': slot + 1, 'group': group, 'logical_offset': slot_bases[slot],
                     'allocated_slots': count, 'allocated_bytes': count * slot_bytes,
                     'payload_bytes': len(payload), 'payload_sha256': digest(payload),
                     'preheader_hex': preheader.hex(), 'header_crc32': f'{header_crc:08x}',
                     '_payload': payload})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    input_digest = filehash(args.input)
    shutil.copyfile(args.input, args.output)
    with args.output.open('r+b') as out:
        for row in plan:
            payload = row.pop('_payload')
            for off in range(0, len(payload), PAGE):
                page = (row['logical_offset'] + off) // PAGE
                out.seek(page * STRIDE)
                out.write(payload[off:off + PAGE])
            verify = hashlib.sha256()
            for off in range(0, len(payload), PAGE):
                page = (row['logical_offset'] + off) // PAGE
                out.seek(page * STRIDE)
                verify.update(out.read(min(PAGE, len(payload) - off)))
            if verify.hexdigest() != row['payload_sha256']:
                raise ValueError('seed verification failed')
    changed_pages = 0
    with args.input.open('rb') as before, args.output.open('rb') as after:
        page_index = 0
        while original := before.read(STRIDE):
            seeded = after.read(STRIDE)
            logical = page_index * PAGE
            allowed = any(r['logical_offset'] <= logical < r['logical_offset'] + r['payload_bytes'] for r in plan)
            if original[PAGE:] != seeded[PAGE:]:
                raise ValueError('OOB changed during offline seed')
            if not allowed and original != seeded:
                raise ValueError('page outside source regions changed during offline seed')
            changed_pages += original != seeded
            page_index += 1
    if filehash(args.input) != input_digest:
        raise ValueError('input changed during seed; stop guest before preparing an offline image')
    content = ('HARMONY=' + str(args.skin)).encode('ascii') + b'\0'
    if len(content) != 12:
        raise ValueError('native configuration writer emits exactly12 bytes; require three-digit skin')
    args.ini.parent.mkdir(parents=True, exist_ok=True)
    if args.ini.exists() and args.ini.read_bytes() != content:
        raise ValueError('refusing to replace different native harmony selection')
    args.ini.write_bytes(content)
    report = {'input': str(args.input), 'input_sha256': input_digest,
              'output': str(args.output), 'output_sha256': filehash(args.output),
              'mapping_source': str(mapping_path), 'mapping_sha256': filehash(mapping_path),
              'mapping': mapping, 'regions': plan, 'all_oob_preserved': True,
              'unwritten_data_pages_preserved': True,
              'preservation_verified_pages': page_index, 'changed_pages': changed_pages,
              'harmony_ini': {'path': str(args.ini), 'hex': content.hex(), 'generated': True,
                              'semantics': 'Native skin selection, not a launch script'},
              'evidence': {'kernel_CheckBigHarmonyInfFile': '0x25e594..0x25e7b4 constructs0xA8 preheader from original .inf fields',
                           'kernel_WriteBigHarmony': '0x25ef9c..0x25eff4 copies source[0x800:] to firstpage+1 and preheader to firstpage',
                           'kernel_slot_base': ('BSP256 GetNandHarmonyAddress0x25e240: slots1/2=0x2dc0000/0x4f60000, 0x10d blocks each' if args.profile == 'audio256' else '0x25e364 maps slots1..6 to documented logical offsets'),
                           'application_writer': 'SaveSkinInHarmonyIniFile0x015c5a08; literal HARMONY=0x02fe8840; default101at0x015c5ae8; write12bytes0x015c5c04',
                           'SSM_reader': 'PreLoadHarmonyFromRawData .text0x16f94..0x16fa4 calls atoi(first_line+8)'},
              'scope': 'A9 '+args.profile+' mapping selected from original package; emulator only.', 'profile':args.profile,
              'NAND_data_MiB': nand_mib}
    args.output.with_suffix(args.output.suffix + '.harmony.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'output': str(args.output), 'regions': len(plan), 'ini': str(args.ini)}))


if __name__ == '__main__':
    main()
