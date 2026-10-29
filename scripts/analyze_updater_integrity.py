#!/usr/bin/env python3
"""Read-only local SMEG integrity audit; never outputs RSA key material.

Checks the original package and emits aggregate integrity evidence only. The
contract is decrypted in memory; neither keys nor plaintext records are saved.
No emulator, physical device, network connection, or firmware mutation is used.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import sys
import zlib

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / 'artifacts/phase2/package/SMEG_PLUS_UPG'
OUT = ROOT / 'artifacts/phase14/security-analysis'
sys.path.insert(0, str(ROOT / 'sources/smeg-plus-patches/tools'))
from patch_contract import find_keys, load_contract, check_of
from smeglib import has_ctrl_layout, has_trailer
from smeg_db_inf import crc16


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def resolve(name):
    parts = name.lstrip('/').split('/')
    if parts[0] == 'SMEG_PLUS_UPG':
        parts.pop(0)
    target = PACKAGE
    for part in parts:
        if part in ('', '.', '..'):
            raise ValueError('Unsafe contract path')
        choices = [p for p in target.iterdir() if p.name.casefold() == part.casefold()]
        if len(choices) != 1:
            raise ValueError('Ambiguous or absent original package member')
        target = choices[0]
    if not target.is_file() or not target.resolve().is_relative_to(PACKAGE):
        raise ValueError('Contract member escaped regular package files')
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to(OUT):
        parser.error('Output must be a new JSON file under phase14/security-analysis')
    app = ROOT / 'artifacts/phase2/applications/AUDIO_BT_256/app.bin'
    keys = find_keys(app.read_bytes())
    header, records, key = load_contract(PACKAGE / 'contract.dat', keys)
    types = Counter()
    matched = 0
    for record in records:
        name = record[:63].split(b'\0', 1)[0].decode()
        payload, _ = check_of(record, resolve(name).read_bytes())
        types[record[63]] += 1
        if record[72:72 + len(payload)] != payload:
            raise ValueError('Original package does not match a contract record')
        matched += 1
    inf_rows = []
    for name in ('UpgPlugin.out', 'upgrade.out', 'upgrade_256.out'):
        payload = PACKAGE / name
        inf = Path(str(payload) + '.inf').read_bytes()
        meta = int(inf[:4], 16) == crc16(inf[4:])
        content = int(inf[4:8], 16) == crc16(payload.read_bytes())
        if not (meta and content):
            raise ValueError('Original native executable sidecar mismatch')
        inf_rows.append({'file': name, 'metadata_crc16_valid': meta,
                         'payload_crc16_valid': content})
    controls = []
    for path in sorted(PACKAGE.rglob('*ctrl.bin')):
        data = path.read_bytes()
        if not has_ctrl_layout(data) or not has_trailer(data):
            raise ValueError('Original control layout/trailer mismatch')
        controls.append({'file': str(path.relative_to(PACKAGE)),
                         'entry_count': struct.unpack_from('>I', data, 44)[0],
                         'trailing_crc32_valid': zlib.crc32(data[:-4]) == struct.unpack_from('>I', data, len(data)-4)[0]})
    report = {
        'scope': 'Read-only original package audit; no physical-device or VM access',
        'sources_sha256': {str(p.relative_to(ROOT)): sha(p) for p in [app, PACKAGE/'contract.dat', PACKAGE/'UpgPlugin.out', PACKAGE/'upgrade_256.out', ROOT/'artifacts/phase2/package/SMEG_PLUS_UPG/BSP/SMEG_PLUS_256/vxWorks.bin', ROOT/'artifacts/phase2/filesystems/AUDIO_BT_256/system_data/ssm_boot.out']},
        'contract': {'format': 'RSA-OAEP SHA-1 encrypted records',
                     'modulus_bits': key['n'].bit_length(),
                     'public_exponent': key['e'],
                     'unique_embedded_RSA_moduli': len({k['n'] for k in keys}),
                     'private_exponent_relation_verified': True,
                     'header_bytes': len(header), 'record_count': len(records),
                     'matched_original_records': matched, 'check_type_counts': dict(types),
                     'keys_or_plaintext_saved': False,
                     'interpretation': 'Private-decryption/public-encryption direction; not proof of a vendor digital signature or hardware-rooted boot policy'},
        'native_executable_sidecars': inf_rows,
        'control_files': controls,
        'physical_secure_boot_or_OTP_verified': False,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'report': str(output), 'contract_records_verified': matched,
                      'sidecars_verified': len(inf_rows), 'controls_verified': len(controls)}))


if __name__ == '__main__':
    main()
