#!/usr/bin/env python3
"""Read-only streamed SHA-256 and bounded magic inventory; never extracts or runs files."""
import argparse
import hashlib
import json
import struct
from pathlib import Path


def inspect(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        head = stream.read(4096)
        h.update(head)
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    result = {'path': str(path), 'size': path.stat().st_size, 'sha256': h.hexdigest()}
    magic = 'unknown'
    if head.startswith(b'\x7fELF') and len(head) >= 20:
        magic = 'ELF'
        result['elf_class'] = {1: 32, 2: 64}.get(head[4], 'unknown')
        result['endianness'] = {1: 'little', 2: 'big'}.get(head[5], 'unknown')
        if head[5] in (1, 2):
            machine = struct.unpack_from('<H' if head[5] == 1 else '>H', head, 18)[0]
            result['elf_machine'] = machine
            result['elf_architecture'] = {20: 'PowerPC', 21: 'PowerPC64', 40: 'ARM', 183: 'AArch64'}.get(machine, 'other')
    elif head.startswith(b'BIGHARMONY'):
        magic = 'BIGHARMONY theme container'
    elif head.startswith(b'\x1f\x8b'):
        magic = 'gzip (inspect decompressed format separately)'
    elif head.startswith(b'PK\x03\x04'):
        magic = 'ZIP'
    elif head.startswith(b'7z\xbc\xaf\x27\x1c'):
        magic = '7z'
    elif head.startswith(b'Rar!'):
        magic = 'RAR'
    elif head.startswith(b'SQLite format 3\x00'):
        magic = 'SQLite3'
    elif head.startswith(b'\x27\x05\x19\x56'):
        magic = 'U-Boot legacy image'
    elif head.startswith(b'\xd0\x0d\xfe\xed'):
        magic = 'FDT/FIT (distinguish by parsing tree)'
    elif len(head) >= 263 and head[257:262] == b'ustar':
        magic = 'tar'
    result['magic'] = magic
    if path.name.lower() == 'f_bigquick.bin' and len(head) > 0x802:
        result['app_zlib_candidate_at_0x801'] = (head[0x801] & 0x0f == 8 and int.from_bytes(head[0x801:0x803], 'big') % 31 == 0)
        result['note'] = 'Header hint only; use upstream unpack.py and fingerprint.py to validate.'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path, help='firmware file or already unpacked directory')
    parser.add_argument('--limit', type=int, default=10000, help='maximum files inventoried')
    args = parser.parse_args()
    if args.limit < 1:
        parser.error('--limit must be positive')
    if not args.input.exists():
        parser.error('input does not exist')
    paths = [args.input] if args.input.is_file() else args.input.rglob('*')
    count = 0
    for path in paths:
        if path.is_symlink() or not path.is_file():
            continue
        count += 1
        if count > args.limit:
            raise SystemExit('file limit reached; raise --limit to inventory remaining files')
        try:
            print(json.dumps(inspect(path), sort_keys=True))
        except OSError as exc:
            print(json.dumps({'path': str(path), 'error': str(exc)}))


if __name__ == '__main__':
    main()
