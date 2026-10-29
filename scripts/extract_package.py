#!/usr/bin/env python3
"""Extract a firmware ZIP to a new directory, validating paths and recording hashes."""
import argparse
import hashlib
import json
import shutil
import stat
import zipfile
from pathlib import Path, PurePosixPath


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('archive', type=Path)
    p.add_argument('output', type=Path)
    args = p.parse_args()
    source = args.archive.resolve(strict=True)
    output = args.output.resolve()
    if output.exists():
        p.error('output must be a new directory')
    with source.open('rb') as stream:
        archive_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
    with zipfile.ZipFile(source) as archive:
        names = set()
        for item in archive.infolist():
            path = PurePosixPath(item.filename)
            if path.is_absolute() or '..' in path.parts or '\\' in item.filename:
                raise ValueError('unsafe member path: ' + item.filename)
            if stat.S_ISLNK(item.external_attr >> 16):
                raise ValueError('ZIP symlink rejected: ' + item.filename)
            if path in names:
                raise ValueError('duplicate member: ' + item.filename)
            names.add(path)
        output.mkdir(parents=True)
        records = []
        for item in archive.infolist():
            dest = output / item.filename
            if item.is_dir():
                dest.mkdir(parents=True, exist_ok=True)
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(item) as src, dest.open('xb') as dst:
                shutil.copyfileobj(src, dst, 1024 * 1024)
            with dest.open('rb') as stream:
                digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            records.append({'path': item.filename, 'size': item.file_size,
                            'zip_crc32': f'{item.CRC:08x}', 'sha256': digest})
        report = {'source': str(source), 'size': source.stat().st_size,
                  'sha256': archive_hash, 'zip_crc_verified': True, 'files': records}
        (output / 'extraction-manifest.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({k: v for k, v in report.items() if k != 'files'}))
        print(f'Extracted and ZIP-CRC-verified {len(records)} files into {output}')


if __name__ == '__main__':
    main()
