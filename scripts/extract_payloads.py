#!/usr/bin/env python3
"""Extract packaged gzip/tar payloads and BigQuick images without running firmware."""
import argparse
import gzip
import hashlib
import json
import tarfile
import zlib
from pathlib import Path


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('package', type=Path)
    ap.add_argument('output', type=Path)
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    results = []
    for path in sorted(args.package.rglob('*.bin')):
        relative = path.relative_to(args.package)
        with path.open('rb') as stream:
            magic = stream.read(2)
        if magic == b'\x1f\x8b':
            dest = args.output / 'filesystems' / relative.with_suffix('')
            if dest.exists():
                raise ValueError(f'refusing existing output: {dest}')
            if tarfile.is_tarfile(path):
                with tarfile.open(path, 'r:gz') as archive:
                    members = archive.getmembers()
                    total = sum(m.size for m in members)
                    if total > 8 * 1024**3:
                        raise ValueError('archive exceeds 8 GiB extraction limit')
                    dest.mkdir(parents=True)
                    archive.extractall(dest, filter='data')
                results.append({'source': str(relative), 'format': 'gzip/tar',
                                'output': str(dest), 'members': len(members),
                                'uncompressed_member_bytes': total,
                                'member_list': [{'name': m.name, 'size': m.size, 'type': m.type.decode('ascii', errors='replace')} for m in members]})
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                h = hashlib.sha256()
                total = 0
                with gzip.open(path, 'rb') as src, dest.open('xb') as dst:
                    for block in iter(lambda: src.read(1024**2), b''):
                        total += len(block)
                        if total > 512 * 1024**2:
                            raise ValueError('gzip exceeds 512 MiB limit')
                        h.update(block)
                        dst.write(block)
                results.append({'source': str(relative), 'format': 'gzip/raw',
                                'output': str(dest), 'size': total, 'sha256': h.hexdigest()})
        elif path.name == 'f_BigQuick.bin':
            raw = path.read_bytes()
            d = zlib.decompressobj()
            image = d.decompress(raw[0x801:], 256 * 1024**2)
            if not d.eof:
                raise ValueError('incomplete/oversized application zlib stream')
            image += d.flush()
            dest = args.output / 'applications' / relative.parts[0] / 'app.bin'
            dest.parent.mkdir(parents=True, exist_ok=True)
            with dest.open('xb') as stream:
                stream.write(image)
            results.append({'source': str(relative), 'format': 'zlib at 0x801',
                            'output': str(dest), 'size': len(image),
                            'sha256': hashlib.sha256(image).hexdigest(),
                            'crc32': f'{zlib.crc32(image):08x}',
                            'trailing_bytes': len(d.unused_data)})
        else:
            continue
        print(json.dumps({k: v for k, v in results[-1].items() if k != 'member_list'}), flush=True)
    (args.output / 'payload-manifest.json').write_text(json.dumps(results, indent=2) + '\n')


if __name__ == '__main__':
    main()
