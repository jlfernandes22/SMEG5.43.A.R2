#!/usr/bin/env python3
"""Validate/stage the exact Phase23 native-reset v2 USB after native QEMU proof.

--local-only reads regular local artifacts without importing device configuration.
The default additionally checks the privately configured USB read-only. --write
requires root, an unmounted exclusive device descriptor, preserved original
exports, and a durable old-prefix backup before replacing that USB prefix.
This prepares USB media only; it does not access the car or certify recovery.
"""
import argparse
import datetime
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import struct
import subprocess
import tempfile
import zlib

from elftools.elf.elffile import ELFFile
from ensure_smeg_fat_lfn import Fat32
from smeg_db_inf import crc16

ROOT = Path(__file__).resolve().parents[1]
PHASE = ROOT / 'artifacts/phase23'
ORIGINAL_RETURN = ROOT / 'artifacts/phase21/physical-theme-install-return-2026-10-29'
IMAGE_BYTES, PARTITION_OFFSET = 135266304, 1048576
EXPECTED_HASHES = {
    'usb.raw': '0030ecdbf832f435e1bf0c09390f8c7448b15ac9326318588346b3d6869b5124',
    'native_reset.out': 'ddba206272eb43fd73a73d7d0b7a6886971003dbc908d6f4b78990c0dd8caa7a',
    'usb_native_reset_probe.c': 'b05d7959c76d5ee6a9a009ab04b1a15d00b40eaa164ed5e74523d1b37cfc8d75',
    'native_reset_contract.h': '44688db3ffc95772b463363a22151bc17061aded0ff3e70fa96de1d7f0d4ddd2',
}
MEMBERS = {'FLYING/native_reset.out', 'FLYING/native_reset.out.inf',
           'FLYING/doctor_smeg_plus_i.inf', 'RESET_PROBE/SENTINEL.TXT'}
IMPORTS = {'fopen', 'fread', 'fwrite', 'fclose', 'fflush', 'ferror', 'mkdir',
           'printf', 'taskDelay', 'sysClkRateGet', 'iosDevFind'}
SENTINEL = b'SMEG_NATIVE_RESET_PROBE_V1\n'
ARMED = (b'ARMED_WAITING_FOR_USB_REMOVAL\n'
         b'One use. This receipt is not proof that reset happened.\n'
         b'No resource, firmware, database or internal filesystem writes requested.\n')
HOST_CASES = {
    'removed': (-11, 1, 7), 'transient': (-11, 1, 10),
    'wrong_fingerprint': (-1, 0, 0), 'wrong_last_fingerprint': (-1, 0, 0),
    'no_usb': (-2, 0, 0), 'default_device': (-2, 0, 0), 'partial_device': (-2, 0, 0),
    'bad_sentinel': (-3, 0, 0), 'missing_sentinel': (-3, 0, 0),
    'bad_clock': (-4, 0, 0), 'duplicate': (-6, 0, 0),
    'write_failure': (-7, 0, 0), 'flush_failure': (-7, 0, 0),
    'close_failure': (-7, 0, 0), 'status_readback': (-7, 0, 0),
    'delay_failure': (-8, 0, 1), 'poll_close_failure': (-9, 0, 1),
    'returned_device': (-10, 0, 7), 'timeout': (-12, 0, 12), 'io_failure': (-12, 0, 12),
}
PROOF_TRUE = ('exact_native_FLYING_execution_verified', 'ARMED_receipt_verified',
              'USB_removed_before_reset', 'native_reset_observed',
              'normal_FM_UI_after_reset_verified', 'theme_resource_ranges_byte_exact')
PROOF_ARTIFACTS = ('native_result', 'serial_log', 'armed_receipt', 'reset_screenshot',
                   'FM_screenshot', 'theme_preservation_audit')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def safe_path(value, root=PHASE, kind='file', new=False):
    """Reject symlinks in every component, including before resolve()."""
    path = Path(value)
    if not path.is_absolute():
        path = ROOT / path
    require(not any(part.is_symlink() for part in (path, *path.parents)),
            'Symlink path component refused')
    path = path.resolve()
    require(path != root and path.is_relative_to(root), 'Artifact path outside permitted directory')
    if new:
        require(not path.exists() and path.parent.is_dir(), 'New preparation directory with existing parent required')
    elif kind == 'directory':
        require(path.is_dir(), 'Required artifact directory missing')
    else:
        require(path.is_file() and stat.S_ISREG(path.stat().st_mode), 'Required regular artifact file missing')
    return path


def read_json(path):
    return json.loads(path.read_text())


def relative_member(value):
    require(isinstance(value, str), 'Invalid relative member path')
    path = PurePosixPath(value)
    require(not path.is_absolute() and value == str(path)
            and all(part not in ('', '.', '..') for part in path.parts), 'Unsafe relative member path')
    return path


def fat_contents(image):
    """Read the regular image directly; never invoke a mount or device tool."""
    contents, directories, visited = {}, set(), set()
    with image.open('rb') as stream:
        fat = Fat32(stream, IMAGE_BYTES)
        require(fat.partition == PARTITION_OFFSET
                and fat.partition_bytes == 128 * 1024**2, 'Unexpected FAT partition geometry')

        def walk(cluster, prefix=''):
            require(cluster not in visited and len(visited) < 8, 'Unexpected FAT directory graph')
            visited.add(cluster)
            for entry in fat.entries(cluster):
                name = entry['lfn'] or entry['short']
                if name in ('.', '..') or entry['attr'] & 8:
                    continue
                require('/' not in name and '\\' not in name and name not in ('', '.', '..'),
                        'Unsafe FAT member name')
                path = prefix + name
                if entry['attr'] & 16:
                    directories.add(path)
                    walk(entry['cluster'], path + '/')
                    continue
                require(path not in contents and entry['bytes'] <= 128 * 1024,
                        'Unexpected FAT member size or duplicate')
                left, chunks = entry['bytes'], []
                if left:
                    for current in fat.clusters(entry['cluster']):
                        take = min(left, fat.cluster_bytes)
                        chunks.append(fat.read(fat.data + (current - 2) * fat.cluster_bytes, take))
                        left -= take
                        if not left:
                            break
                require(left == 0, 'Truncated FAT member')
                contents[path] = b''.join(chunks)

        walk(fat.root)
    require(set(contents) == MEMBERS and directories == {'FLYING', 'RESET_PROBE'},
            'Exactly four fresh reset-probe files and no ARMED guard are required')
    return contents


def audit_module(data, metadata):
    elf = ELFFile(io.BytesIO(data))
    require(elf.elfclass == 32 and not elf.little_endian
            and elf['e_type'] == 'ET_REL' and elf['e_machine'] == 'EM_PPC', 'Wrong native module format')
    table = elf.get_section_by_name('.symtab')
    require(table is not None, 'Native module symbol table missing')
    symbols = list(table.iter_symbols())
    entries = [s for s in symbols if s.name == 'smeg_native_reset_probe']
    require(len(entries) == 1 and entries[0]['st_value'] == 0
            and isinstance(entries[0]['st_shndx'], int)
            and elf.get_section(entries[0]['st_shndx']).name == '.text', 'Native entry is not .text offset zero')
    imports = sorted(s.name for s in symbols if s.name and s['st_shndx'] == 'SHN_UNDEF')
    require(set(imports) == IMPORTS and imports == metadata['module_imports'], 'Native import allowlist mismatch')
    return imports


def validate_host_tests(tests):
    require(tests.get('production_C_control_flow_tested') is True
            and tests.get('firmware_apis_mocked') is True
            and tests.get('physical_reset_proven') is False
            and tests.get('direct_NAND_operations_mocked_or_used') is False, 'Host test scope mismatch')
    rows = tests.get('cases', [])
    require(len(rows) == 20 and {r.get('case') for r in rows} == set(HOST_CASES),
            'All twenty distinct host fault cases are required')
    pre_guard = {'wrong_fingerprint', 'wrong_last_fingerprint', 'no_usb', 'default_device',
                 'partial_device', 'bad_sentinel', 'missing_sentinel', 'bad_clock', 'duplicate'}
    for row in rows:
        name = row['case']
        require((row.get('status'), row.get('reset_calls'), row.get('seconds')) == HOST_CASES[name]
                and row.get('all_streams_closed') is True
                and row.get('armed') == (0 if name in pre_guard else 1)
                and row.get('USB_status_writes') == (0 if name in pre_guard else 1),
                'Host fault-result truth mismatch: ' + name)


def validate_backup(backup):
    require(backup == ORIGINAL_RETURN, 'The independently preserved original physical return is required')
    manifest_path = safe_path(backup / 'copy-manifest.json', ORIGINAL_RETURN)
    manifest = read_json(manifest_path)
    rows = manifest.get('files', [])
    require(manifest.get('read_only_mount') is True
            and manifest.get('all_files_copied_and_hash_verified') is True
            and manifest.get('physical_car_accessed') is False and len(rows) == 43,
            'Original 43-file read-only backup evidence incomplete')
    files = safe_path(backup / 'files', ORIGINAL_RETURN, kind='directory')
    names = [str(relative_member(row['path'])) for row in rows]
    require(len(set(names)) == 43, 'Duplicate original-backup member')
    actual = set()
    for path in files.rglob('*'):
        require(not path.is_symlink(), 'Original backup contains a symlink')
        if path.is_file():
            require(stat.S_ISREG(path.stat().st_mode), 'Original backup has a non-regular member')
            actual.add(str(path.relative_to(files)))
        else:
            require(path.is_dir(), 'Original backup has an unsupported member')
    require(actual == set(names), 'Original backup file inventory changed')
    for row in rows:
        path = safe_path(files / row['path'], ORIGINAL_RETURN)
        require(path.stat().st_size == row['bytes'] and sha(path) == row['sha256'],
                'Original backup content/hash changed: ' + row['path'])
    for bank, name, uid in ((1, b'SQUARE', 10), (2, b'WARMLIGHT', 11)):
        stem = files / f'SMEG_BACKUP/original-bank{bank}-entry1'
        header = safe_path(str(stem) + '.header', ORIGINAL_RETURN).read_bytes()
        payload = safe_path(str(stem) + '.bin', ORIGINAL_RETURN).read_bytes()
        require(len(header) == 216 and header[:196].split(b'\0')[0] == name
                and struct.unpack_from('>I', header, 200)[0] == uid
                and struct.unpack_from('>II', header, 208) == (len(payload), zlib.crc32(payload)),
                'Original theme payload/header/CRC invalid')
    return manifest_path, rows


def validate_reset_chain(result, serial):
    """Corroborate an actual guest GPIO reset without inventing UART output."""
    begin, armed = serial.find('SMEG_NATIVE_RESET_BEGIN'), serial.find('SMEG_NATIVE_RESET_ARMED')
    require(0 <= begin < armed and 'SMEG_NATIVE_RESET_ABORT' not in serial
            and 'SMEG_NATIVE_RESET_TIMEOUT' not in serial, 'Native BEGIN/ARMED serial sequence failed')
    require(result.get('physical_devices_accessed') is False
            and result.get('guest_RAM_or_instruction_patches') is False
            and result.get('guest_PC_redirected') is False
            and result.get('fatal_guest_exceptions') == []
            and result.get('native_GPIO_reset_log_seen') is True, 'Native runtime evidence has patches/failures or lacks GPIO reset')
    events = result.get('QMP_events', [])
    resets = [row for row in events if row.get('event') == 'RESET']
    require(len(resets) == 1 and resets[0].get('data', {}).get('guest') is True
            and resets[0]['data'].get('reason') == 'guest-reset', 'Exactly one actual guest QMP reset required')

    def event_time(row):
        stamp = row['timestamp']
        return stamp['seconds'] + stamp['microseconds'] / 1_000_000

    reset_at = event_time(resets[0])
    detached = [event_time(row) for row in events if row.get('event') == 'DEVICE_DELETED'
                and event_time(row) < reset_at]
    require(detached and 4 <= reset_at - max(detached) < 180,
            'USB deletion must precede native reset by five phased one-second polls within timeout')


def validate_proof(candidate, proof_path, metadata):
    proof = read_json(proof_path)
    require(proof.get('schema') == 'smeg-native-reset-v2-proof-1'
            and safe_path(proof['candidate_directory'], kind='directory') == candidate, 'Wrong integration proof/candidate')
    for key, name in (('candidate_USB_sha256', 'usb.raw'), ('module_sha256', 'native_reset.out'),
                      ('source_sha256', 'usb_native_reset_probe.c'), ('contract_sha256', 'native_reset_contract.h')):
        require(proof.get(key) == EXPECTED_HASHES[name], 'Integration proof does not bind exact v2 bytes')
    require(all(proof.get(key) is True for key in PROOF_TRUE)
            and proof.get('debugger_RAM_or_instruction_patches') is False
            and proof.get('guest_PC_redirected') is False
            and proof.get('physical_devices_accessed') is False
            and proof.get('physical_reset_proven') is False
            and proof.get('fatal_guest_exceptions') == [], 'Native integration acceptance is incomplete')
    require(proof.get('stalled_used_USB_hotplug_verified') is True,
            'Exact helper hotplug into the already-stalled used-USB state has not passed')
    require(proof.get('status') == 'PASS', 'Final integration proof must explicitly report PASS')
    evidence = proof.get('evidence', [])
    require(evidence, 'Hash-bound integration evidence missing')
    bound = {}
    for row in evidence:
        path = safe_path(row['path'])
        require(path not in bound and sha(path) == row['sha256'], 'Duplicate or changed integration evidence')
        bound[path] = row['sha256']
    for name in (*EXPECTED_HASHES, 'usb.json'):
        require(candidate / name in bound, 'Candidate file absent from bound integration evidence: ' + name)
    artifacts = {}
    for key in PROOF_ARTIFACTS:
        path = safe_path(proof['artifacts'][key])
        require(path in bound, 'Required integration artifact not hash-bound: ' + key)
        artifacts[key] = path
    require(artifacts['armed_receipt'].read_bytes() == ARMED, 'Native ARMED receipt/readback differs')
    serial = artifacts['serial_log'].read_text(errors='replace')
    result = read_json(artifacts['native_result'])
    validate_reset_chain(result, serial)
    request = 'SMEG_NATIVE_RESET_REQUEST original EmergencyReboot; USB absent checks=5; no open streams'
    if request in serial:
        require(serial.find(request) > serial.find('SMEG_NATIVE_RESET_ARMED')
                and proof.get('request_serial_marker_present') is True, 'Reset request marker/order differs')
    else:
        require(proof.get('proof_policy') == 'exact_native_chain_with_unretained_request_serial_v1'
                and proof.get('request_serial_marker_present') is False
                and proof.get('request_serial_marker_missing_explanation')
                == 'UART output may have been lost during reset; cause unverified'
                and proof.get('original_strict_assertion_preserved') is True,
                'Missing request UART marker needs explicit equivalent-chain acceptance and limitation')
        strict_path = safe_path(proof['original_strict_result'])
        require(strict_path in bound, 'Original strict assertion evidence is not hash-bound')
        strict = read_json(strict_path)
        require(strict.get('error') == 'AssertionError()'
                and strict.get('native_markers', {}).get('SMEG_NATIVE_RESET_REQUEST') is False,
                'Original missing-marker strict failure was not preserved')
    audit = read_json(artifacts['theme_preservation_audit'])
    require(audit.get('all_theme_resource_ranges_byte_exact') is True
            and audit.get('includes_OOB') is True, 'Full theme-range preservation audit missing')
    ranges = audit.get('ranges', [])
    require(len(ranges) == 2 and {row.get('bank') for row in ranges} == {1, 2}, 'Both complete theme ranges required')
    for row in ranges:
        logical = {1: 0x2dc0000, 2: 0x4f60000}[row['bank']]
        require(row.get('offset') == logical // 2048 * 2112
                and row.get('bytes') == 0x21a0000 // 2048 * 2112
                and isinstance(row.get('before_sha256'), str) and len(row['before_sha256']) == 64
                and row['before_sha256'] == row.get('after_sha256'), 'Theme-range bytes changed or coverage differs')
    for key in ('source_NAND_sha256', 'after_NAND_sha256'):
        require(isinstance(audit.get(key), str) and len(audit[key]) == 64, 'Preservation NAND identity missing')
    hotplug_path = safe_path(proof['stalled_hotplug_proof'])
    require(hotplug_path in bound, 'Stalled-state hotplug proof is not hash-bound')
    hotplug = read_json(hotplug_path)
    require(hotplug.get('schema') == 'smeg-native-reset-v2-stalled-hotplug-proof-1'
            and hotplug.get('status') == 'PASS'
            and hotplug.get('stalled_used_USB_hotplug_verified') is True
            and hotplug.get('candidate_USB_sha256') == EXPECTED_HASHES['usb.raw']
            and hotplug.get('module_sha256') == EXPECTED_HASHES['native_reset.out']
            and all(hotplug.get(key) is True for key in PROOF_TRUE)
            and hotplug.get('debugger_RAM_or_instruction_patches') is False
            and hotplug.get('guest_PC_redirected') is False
            and hotplug.get('physical_devices_accessed') is False
            and hotplug.get('physical_reset_proven') is False
            and hotplug.get('fatal_guest_exceptions') == [], 'Stalled used-USB state-match evidence incomplete')
    hotplug_artifacts = {}
    for key in PROOF_ARTIFACTS:
        path = safe_path(hotplug['artifacts'][key])
        require(path in bound, 'State-match artifact is not bound in final proof: ' + key)
        hotplug_artifacts[key] = path
    require(hotplug_artifacts['armed_receipt'].read_bytes() == ARMED, 'State-match ARMED receipt differs')
    hotplug_serial = hotplug_artifacts['serial_log'].read_text(errors='replace')
    guard = hotplug_serial.find('SMEG_RO_BACKUP_ABORT: destination already exists or cannot be created')
    require(0 <= guard < hotplug_serial.find('SMEG_NATIVE_RESET_BEGIN'),
            'State-match run lacks the old used-USB guard abort before helper hotplug')
    validate_reset_chain(read_json(hotplug_artifacts['native_result']), hotplug_serial)
    hotplug_audit = read_json(hotplug_artifacts['theme_preservation_audit'])
    require(hotplug_audit.get('all_theme_resource_ranges_byte_exact') is True
            and hotplug_audit.get('includes_OOB') is True
            and hotplug_audit.get('ranges') == ranges,
            'State-match reset changed theme ranges or used different source banks')
    return proof


def validate_local(candidate, proof_path, backup):
    image = safe_path(candidate / 'usb.raw')
    metadata_path = safe_path(candidate / 'usb.json')
    metadata = read_json(metadata_path)
    require(image.stat().st_size == IMAGE_BYTES and metadata.get('image_bytes') == IMAGE_BYTES
            and metadata.get('partition_offset_bytes') == PARTITION_OFFSET, 'Candidate geometry mismatch')
    for name, expected in EXPECTED_HASHES.items():
        require(sha(safe_path(candidate / name)) == expected, 'Exact reset-v2 candidate changed: ' + name)
    source = ROOT / 'emulation/usb_native_reset_probe.c'
    require(safe_path(source, ROOT) == source and sha(source) == EXPECTED_HASHES[source.name], 'Current reset C source changed')
    for key, name in (('image_sha256', 'usb.raw'), ('module_sha256', 'native_reset.out'),
                      ('source_sha256', source.name), ('frozen_source_sha256', source.name),
                      ('contract_sha256', 'native_reset_contract.h')):
        require(metadata.get(key) == EXPECTED_HASHES[name], 'Candidate metadata hash mismatch')
    for key in ('physical_device_access', 'physical_car_approved', 'physical_reset_proven',
                'resources_or_databases_restored', 'direct_NAND_write_API_included',
                'internal_filesystem_writes_requested', 'application_or_MMI_API_dependency',
                'USER_DATA_dependency', 'USB_descriptor_self_disarmed'):
        require(metadata.get(key) is False, 'Reset-only scope changed: ' + key)
    require(metadata.get('wait_seconds') == 180 and metadata.get('absent_checks') == 5
            and metadata.get('ELF_entry_offset') == 0, 'Reset/removal control contract changed')
    validate_host_tests(metadata.get('host_tests', {}))
    contents = fat_contents(image)
    rows = metadata.get('files', [])
    require(len(rows) == 4 and {row.get('path') for row in rows} == MEMBERS, 'Candidate member manifest changed')
    for row in rows:
        data = contents[row['path']]
        require(len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256'], 'FAT member hash mismatch')
    payload = contents['FLYING/native_reset.out']
    require(payload == (candidate / 'native_reset.out').read_bytes() and contents['RESET_PROBE/SENTINEL.TXT'] == SENTINEL,
            'FAT module or sentinel differs')
    imports = audit_module(payload, metadata)
    body = (f'{crc16(payload):04x}\r\nVER:SMEG5.43.A.R2\r\nTYPE:RELOCABLE\r\nID:0\r\n'
            f'COMPRESSED:NO\r\nSIZE:{len(payload)}\r\nENTRY:YES\r\n').encode()
    doctor = b'0000\r\nACTION:TemporaryBootRom\r\nLOAD_AND_EXECUTE:/bd0/FLYING/native_reset.out\r\n'
    for name, expected in (('FLYING/native_reset.out.inf', body), ('FLYING/doctor_smeg_plus_i.inf', doctor)):
        require(contents[name] == f'{crc16(expected):04x}'.encode() + expected, 'Native descriptor/CRC differs')
    # Rebuild using an explicit command, never an executable command from JSON.
    with tempfile.TemporaryDirectory(prefix='smeg-reset-stage-rebuild-') as directory:
        rebuilt = Path(directory) / 'native_reset.out'
        command = ['clang', '--target=powerpc-unknown-linux-gnu', '-mbig-endian', '-m32', '-mlongcall',
                   '-ffreestanding', '-fno-pic', '-fno-stack-protector', '-fno-unwind-tables',
                   '-fno-asynchronous-unwind-tables', '-msoft-float', '-O2', '-Wall', '-Wextra', '-Werror',
                   '-I', str(candidate), '-c', str(candidate / source.name), '-o', str(rebuilt)]
        subprocess.run(command, check=True, capture_output=True)
        require(rebuilt.read_bytes() == payload, 'Frozen C/contract do not reproduce exact module')
    proof = validate_proof(candidate, proof_path, metadata)
    manifest_path, backup_rows = validate_backup(backup)
    return image, metadata, proof, manifest_path, backup_rows, imports


def durable_receipt(path, report):
    """Persist progress/error evidence before proceeding with a USB mutation."""
    with tempfile.NamedTemporaryFile('w', dir=path.parent, prefix='.receipt-', delete=False) as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
        temporary = Path(stream.name)
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def durable_original_backup(backup, rows):
    directories = {backup, backup / 'files'}
    for row in rows:
        path = safe_path(backup / 'files' / row['path'], ORIGINAL_RETURN)
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
            require(os.fstat(stream.fileno()).st_size == row['bytes']
                    and hashlib.file_digest(stream, 'sha256').hexdigest() == row['sha256'], 'Original export changed before staging')
            os.fsync(stream.fileno())
        directories.update(p for p in path.parents if p == backup or p.is_relative_to(backup))
    for path in sorted(directories, key=lambda p: len(p.parts), reverse=True):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def main():
    require(__debug__, 'Run without Python optimization; FAT parser assertions are required')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--proof', type=Path, required=True)
    parser.add_argument('--backup', type=Path, required=True)
    parser.add_argument('--preparation', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--local-only', action='store_true')
    mode.add_argument('--write', action='store_true')
    args = parser.parse_args()
    candidate = safe_path(args.candidate, kind='directory')
    proof_path = safe_path(args.proof)
    backup = safe_path(args.backup, ROOT / 'artifacts/phase21', kind='directory')
    preparation = safe_path(args.preparation, new=True)
    require(not any(preparation == p or preparation.is_relative_to(p) or p.is_relative_to(preparation)
                    for p in (candidate, backup, proof_path.parent)), 'Preparation directory must be separate from inputs')
    image, metadata, proof, manifest_path, backup_rows, imports = validate_local(candidate, proof_path, backup)
    report = dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  scope='USB preparation only; original native reset after removal; no firmware/resource restore',
                  candidate=str(candidate), image_sha256=metadata['image_sha256'], image_bytes=IMAGE_BYTES,
                  module_sha256=metadata['module_sha256'], source_sha256=metadata['source_sha256'],
                  contract_sha256=metadata['contract_sha256'], module_imports=imports,
                  proof=str(proof_path), proof_sha256=sha(proof_path), host_fault_cases_verified=20,
                  original_export_backup=str(backup), original_export_files_verified=len(backup_rows),
                  original_export_manifest_sha256=sha(manifest_path), USB_written=False,
                  physical_car_accessed=False, physical_reset_proven=False,
                  physical_car_recovery_certified=False, resource_or_application_writes_requested=False,
                  normal_native_reset_bookkeeping_may_write_internally=True,
                  device_configuration_or_identifiers_in_output=False, phase='local_validation_passed')
    if args.local_only:
        report['physical_USB_inspected'] = False
        print(json.dumps(report, indent=2))
        return
    # Lazy imports keep --local-only independent of private USB configuration
    # and avoid every device-discovery call until all local proofs pass.
    from prepare_verified_theme_usb import DEVICE, device_state, validate_open_device, validate_open_source
    from prepare_warmlight_test_usb import verify_prefix, replace_prefix
    device, mounted = device_state()
    report.update(physical_USB_inspected=True, private_USB_identity_verified=True,
                  USB_has_mounts=bool(mounted), phase='read_only_device_preflight_passed')
    if not args.write:
        print(json.dumps(report, indent=2))
        return
    require(os.geteuid() == 0, 'Administrator authentication required')
    require(not mounted, 'Unmount the privately identified USB before staging')
    durable_original_backup(backup, backup_rows)
    with os.fdopen(os.open(image, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as source:
        validate_open_source(source, metadata['image_sha256'], IMAGE_BYTES)
        device, mounted = device_state()
        require(not mounted, 'Identified USB became mounted')
        fd = os.open(DEVICE, os.O_RDWR | os.O_EXCL)
        try:
            validate_open_device(fd, device)
            safe_path(preparation, new=True)
            preparation.mkdir(mode=0o700)
            saved, receipt = preparation / 'original-prefix.raw', preparation / 'preparation.json'
            report.update(original_prefix_backup=str(saved), USB_write_started=False)
            try:
                left, digest = IMAGE_BYTES, hashlib.sha256()
                os.lseek(fd, 0, os.SEEK_SET)
                with saved.open('xb') as stream:
                    while left:
                        data = os.read(fd, min(left, 8 << 20))
                        require(data, 'Short current USB prefix read')
                        require(stream.write(data) == len(data), 'Short host prefix backup write')
                        digest.update(data)
                        left -= len(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                require(saved.stat().st_size == IMAGE_BYTES and sha(saved) == digest.hexdigest(), 'Old USB prefix backup failed')
                report['original_prefix_sha256'] = verify_prefix(fd, IMAGE_BYTES, digest.hexdigest())
                report.update(original_prefix_backup_verified=True, phase='backup_verified_before_write')
                durable_receipt(receipt, report)
                # Revalidate the held source immediately before the first write.
                validate_open_source(source, metadata['image_sha256'], IMAGE_BYTES)
                report.update(USB_write_started=True, phase='writing_exact_tested_prefix')
                durable_receipt(receipt, report)
                report['readback_sha256'] = replace_prefix(fd, source, IMAGE_BYTES, metadata['image_sha256'])
                report.update(USB_written=True, readback_verified=True, phase='complete')
                fcntl.ioctl(fd, 0x125f)  # BLKRRPART, after full prefix readback.
            except BaseException as error:
                # Exception messages can contain private device paths: retain
                # only the exception type in the receipt and public output.
                report.update(phase='failed_do_not_use_USB', error_type=type(error).__name__)
                durable_receipt(receipt, report)
                raise
            durable_receipt(receipt, report)
        finally:
            os.close(fd)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    try:
        main()
    except ValueError as error:
        raise SystemExit(str(error)) from None
    except Exception as error:
        raise SystemExit('USB preparation did not complete; error type: ' + type(error).__name__) from None
