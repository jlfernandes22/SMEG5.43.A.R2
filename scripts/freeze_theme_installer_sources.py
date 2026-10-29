#!/usr/bin/env python3
"""Freeze the actual compiler include closure and reproduce the installer ELF."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', type=Path, required=True)
    args = parser.parse_args()
    candidate = args.candidate.resolve()
    assert candidate.is_relative_to(ROOT / 'artifacts/phase20')
    metadata = json.loads((candidate / 'usb.json').read_text())
    command = metadata['compile_command']
    entry = Path(command[command.index('-c') + 1]).resolve()
    module = Path(command[command.index('-o') + 1]).resolve()
    dependency_command = []
    skip = False
    for item in command:
        if skip:
            skip = False
            continue
        if item == '-o':
            skip = True
            continue
        if item != '-c':
            dependency_command.append(item)
    dependency_command.append('-MM')
    deps = subprocess.check_output(dependency_command, text=True)
    sources = shlex.split(deps.split(':', 1)[1].replace('\\\n', ' '))
    snapshot = candidate / 'source-snapshot'
    assert not snapshot.exists()
    snapshot.mkdir()
    manifest = {}
    for name in sources:
        path = Path(name).resolve()
        assert path.is_relative_to(ROOT) and path.is_file() and not Path(name).is_symlink()
        assert path.name not in manifest
        shutil.copyfile(path, snapshot / path.name)
        manifest[path.name] = dict(source=str(path.relative_to(ROOT)), sha256=sha(path))
    (snapshot / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    with tempfile.TemporaryDirectory(prefix='smeg-frozen-installer-') as temp:
        rebuilt = Path(temp) / module.name
        frozen_command = [str(snapshot) if item in (str(candidate), str(ROOT / 'emulation'))
                          else str(snapshot / entry.name) if item == str(entry)
                          else str(rebuilt) if item == str(module) else item for item in command]
        subprocess.run(frozen_command, check=True)
        assert rebuilt.read_bytes() == module.read_bytes(), 'Frozen source closure does not reproduce tested ELF'
    for name, row in manifest.items():
        assert sha(snapshot / name) == row['sha256'] == sha(ROOT / row['source'])
    proof = dict(source_files=len(manifest), manifest_sha256=sha(snapshot / 'manifest.json'),
                 module_sha256=sha(module), frozen_source_rebuild_byte_exact=True,
                 frozen_compile_command=[str(snapshot / 'rebuilt.out') if item == str(rebuilt) else item
                                         for item in frozen_command])
    (snapshot / 'rebuild-proof.json').write_text(json.dumps(proof, indent=2) + '\n')
    print(json.dumps(proof))


if __name__ == '__main__':
    main()
