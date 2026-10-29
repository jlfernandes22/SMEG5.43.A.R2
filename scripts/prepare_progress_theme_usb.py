#!/usr/bin/env python3
"""Validate/stage an exact tested native theme installer on the known Verbatim.

Default preflight is read-only. --local-only validates artifacts without any
device inspection. --write replaces the identified, unmounted USB prefix only
after root authentication, an exclusive identity check and a durable backup;
the complete written prefix is read back independently. This script never
accesses the car and does not establish recovery from interrupted NAND writes.
"""
import argparse
import datetime
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import zlib

from elftools.elf.elffile import ELFFile
from prepare_verified_theme_usb import (
    ROOT, DEVICE, SERIAL, require, device_state, validate_open_device,
    validate_open_source,
)
from prepare_warmlight_test_usb import verify_prefix, replace_prefix
from smeg_db_inf import crc16

IMAGE_BYTES = 135266304
SOURCE_CHECK_BACKUP = ROOT / 'artifacts/phase21/physical-retry-readonly-return-2026-10-29'
THEMES = {1: 'GRAPHIC', 2: 'ELLIPTIC', 3: 'CUBIC', 4: 'REFLEX',
          7: 'ESSENTIEL', 8: 'REDLINE', 10: 'SQUARE', 11: 'WARMLIGHT'}
EXTRAS = (1, 2, 3, 4, 7, 8)
MEMBERS = {
    'FLYING/theme_resources.out', 'FLYING/theme_resources.out.inf',
    'FLYING/doctor_smeg_plus_i.inf',
    *[f'THEME_TEST/bank{bank}.bin' + suffix for bank in (1, 2) for suffix in ('', '.inf')],
    *[f'PREVIEWS/theme{uid}.jpg' for uid in EXTRAS],
}
SOURCE_CLOSURE_MINIMUM = {
    'usb_complete_themes_sandbox.c', 'usb_install_theme_resources_sandbox.c',
    'theme_source_verify.h', 'theme_install_progress.h', 'theme_progress_contract.h',
    'usb_backup_readonly.c', 'usb_theme_previews_sandbox.c',
    'usb_extra_theme_flags_sandbox.c', 'usb_set_theme_catalogue_sandbox.c',
    'usb_refresh_theme_catalogue_sandbox.c', 'theme_resource_contract.h',
    'theme_preview_contract.h', 'theme_preview_fs_contract.h',
    'usb_warmlight_api_fingerprints.h', 'theme_common_catalogue_contract.h',
    'theme_catalogue_contract.h',
}
ALLOWED_IMPORTS = {
    'closedir', 'errnoGet', 'fclose', 'ferror', 'fflush', 'fopen', 'fprintf',
    'fread', 'free', 'fwrite', 'malloc', 'mkdir', 'opendir', 'printf', 'remove',
    'snprintf', 'strcmp', 'sysClkRateGet', 'taskDelay',
}
REQUIRED_FUNCTIONS = {
    'smeg_usb_readonly_backup', 'smeg_complete_theme_install',
    'smeg_install_theme_resources', 'smeg_copy_new_theme_previews',
    'smeg_emulator_extra_theme_flags', 'smeg_set_theme_catalogue',
    'smeg_refresh_theme_catalogue',
}


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def safe_file(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink()
            and path.resolve().is_relative_to(ROOT / 'artifacts'), 'Unsafe artifact: ' + str(path))
    return path


def read_json(path):
    return json.loads(safe_file(path).read_text())


def artifact_path(value):
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def mtool(image, tool, *args):
    return subprocess.check_output(
        ['/usr/bin/' + tool, '-i', str(image) + '@@1048576', *args],
        env=dict(os.environ, MTOOLS_SKIP_CHECK='1'),
    )


def expected_catalogue():
    result = []
    for uid, number, code in [(1, 1, 102), (2, 1, 202), (3, 2, 203),
                              (4, 3, 204), (7, 3, 104), (8, 2, 103)]:
        result.extend([
            dict(Section='supervisor', Name=f'harmony{uid}', Idx=0, StringValue=THEMES[uid]),
            dict(Section='supervisor', Name=f'harm{uid}_number', Idx=0, IntValue=number),
            dict(Section='supervisor', Name=f'harm{uid}_offset_area', Idx=0, IntValue=code),
        ])
    return result


def check_crc(data, inf, name):
    require(len(inf) >= 8 and inf[:4] == f'{crc16(inf[4:]):04x}'.encode()
            and inf[4:8] == f'{crc16(data):04x}'.encode(), 'INF/file CRC mismatch: ' + name)


def audit_installer(payload, meta):
    elf = ELFFile(io.BytesIO(payload))
    require(elf.elfclass == 32 and not elf.little_endian
            and elf['e_machine'] == 'EM_PPC' and elf['e_type'] == 'ET_REL',
            'Wrong native relocatable module architecture')
    symbols = list(elf.get_section_by_name('.symtab').iter_symbols())
    defined = {s.name: s for s in symbols if s.name and s['st_shndx'] not in ('SHN_UNDEF', 'SHN_ABS')}
    require(REQUIRED_FUNCTIONS <= defined.keys(), 'Full native installer steps absent')
    first = defined['smeg_usb_readonly_backup']
    require(first['st_value'] == 0 and elf.get_section(first['st_shndx']).name == '.text',
            'Original backup must be the module entry')
    imports = sorted(s.name for s in symbols if s.name and s['st_shndx'] == 'SHN_UNDEF')
    require(set(imports) <= ALLOWED_IMPORTS, 'Unsupported native imports: ' + repr(imports))
    require(meta['complete_stock_to_eight_theme_installer'] is True
            and meta['full_native_payload_backup_and_readback'] is True
            and meta['native_full_resource_bank_erasure'] is True
            and meta['native_per_bank_header_erasure'] is False
            and meta['native_theme_catalogue_registration'] is True
            and meta['generated_theme_cache_marker_invalidated'] is True
            and meta['removed_cache_marker'] == '/SYSTEM_TMP_DATA/HarmoniesChecked.tst',
            'Unexpected installer mechanism')
    require(meta['replacement_databases'] is False and meta['application_or_BSP_writes'] is False
            and meta['auto_reboot'] is False, 'Unexpected binary/database replacement or reboot')
    require(meta.get('source_sidecar_preflight') is True,
            'Both bank INF sidecars must be validated before any erasure')
    require(meta['requested_configuration_flags'] == [f'display.Harm_{uid}.0=1' for uid in EXTRAS]
            and meta['requested_theme_catalogue_rows'] == expected_catalogue(),
            'Unexpected configuration/catalogue request')
    require(meta.get('native_progress_contract') and meta['configuration_setters'] is True,
            'Native theme/progress implementation missing')
    progress = meta['native_progress_contract']
    require(progress.get('progress_control') == 1000 and progress.get('progress_range') == [0, 100]
            and progress.get('native_update_numeric') == '0x02734a80'
            and progress.get('BCM_progress_setters_called') is False
            and progress.get('percent_callback_file_IO') is False
            and progress.get('detail_callback_file_IO') is False,
            'Guarded native moving-progress contract missing')
    return imports


def audit_banks(contents, candidate, meta):
    require({row['bank'] for row in meta['banks']} == {1, 2} and len(meta['banks']) == 2,
            'Both replacement banks required')
    expected_uids = {1: [10, 1, 8, 7], 2: [11, 2, 3, 4]}
    result = []
    for row in meta['banks']:
        bank = row['bank']
        name = f'THEME_TEST/bank{bank}.bin'
        data, inf = contents[name], contents[name + '.inf']
        require(len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256']
                and data == safe_file(candidate / f'bank{bank}.bin').read_bytes(), 'Bank changed')
        check_crc(data, inf, name)
        require(data.startswith(b'BIGHARMONY') and len(data) > 2300, 'Invalid bank format')
        fields = dict(line.split(':', 1) for line in inf.decode('ascii').splitlines() if ':' in line)
        count = struct.unpack_from('>I', data, 2080)[0]
        header_size = int(fields['HEADER_SIZE'])
        require(count == 4 and header_size == 36 + count * 216
                and zlib.crc32(data[2048:2048 + header_size]) == int(fields['HEADER_CRC32']) & 0xffffffff,
                'Invalid bank directory/CRC')
        original = safe_file(ROOT / f'artifacts/phase2/package/SMEG_PLUS_UPG/HARMONY/BigHarmony_{bank + 3}/BIG_HARMONY.bin').read_bytes()
        opage, osize = struct.unpack_from('>II', original, 2084 + 204)
        original_payload = original[opage * 2048:opage * 2048 + osize]
        observed = []
        for index in range(count):
            entry = data[2084 + index * 216:2084 + (index + 1) * 216]
            uid, page, size, crc = struct.unpack_from('>IIII', entry, 200)
            theme = entry[:196].split(b'\0')[0].decode('ascii')
            lo, hi = page * 2048, page * 2048 + size
            require(uid == expected_uids[bank][index] and theme == THEMES[uid]
                    and size > 0 and lo >= 2048 + header_size and hi <= len(data), 'Wrong theme entry')
            payload = data[lo:hi]
            require(zlib.crc32(payload) == crc, 'Compressed theme payload CRC mismatch')
            if index == 0:
                require(payload == original_payload, 'Original SQUARE/WARMLIGHT payload changed')
            observed.append(dict(uid=uid, name=theme, bytes=size, sha256=hashlib.sha256(payload).hexdigest()))
        require(row['original_first_payload_preserved'] is True, 'Stock preservation not recorded')
        result.append(dict(bank=bank, entries=observed, stock_first_payload_exact=True))
    return result


def check_sidecar_receipts(contents, native_run):
    text = mtool(native_run / 'usb.raw', 'mtype', '::/SMEG_BACKUP/source-checks.txt').decode()
    rows = [dict(re.findall(r'(\w+)=(\S+)', line)) for line in text.splitlines()
            if line.startswith('SOURCE_CHECK ')]
    checked = []
    for bank in (1, 2):
        name = f'THEME_TEST/bank{bank}.bin.inf'
        matching = [row for row in rows if row.get('path') == '/bd0/' + name]
        require(len(matching) >= 2, 'Missing two pre-erase INF verification receipts: ' + name)
        clean = matching[-2:]
        require([int(row['consecutive']) for row in clean] == [1, 2]
                and int(clean[1]['attempt']) == int(clean[0]['attempt']) + 1
                and int(clean[1]['attempt']) <= 3, 'INF did not obtain two consecutive valid passes')
        expected_crc = f'{zlib.crc32(contents[name]):08x}'
        for row in clean:
            require(row['opened'] == '1' and int(row['bytes']) == int(row['expected_bytes']) == len(contents[name])
                    and row['CRC32'].lower() == row['expected_crc'].lower() == expected_crc
                    and row['ferror'] == '0' and row['fclose'] == '0'
                    and row.get('progress_error', '0') == '0', 'Failed INF verification receipt: ' + name)
        checked.append(dict(path=name, bytes=len(contents[name]), CRC32=expected_crc,
                            verified_consecutive_passes=2))
    return checked


def check_audits(proof, bound_evidence):
    names = {'installed_resources', 'installed_settings', 'cold_resources', 'cold_settings', 'visual'}
    require(set(proof['audits']) == names, 'Required install/cold audits missing')
    data = {}
    for name, value in proof['audits'].items():
        path = safe_file(artifact_path(value))
        require(str(path.resolve()) in bound_evidence, 'Audit not bound in proof evidence')
        data[name] = read_json(path)
    for name in ('installed_resources', 'cold_resources'):
        audit = data[name]
        require(audit['native_install_success'] is True and audit['original_application_byte_exact'] is True
                and audit['all_seven_databases_valid'] is True and audit['non_theme_setting_differences'] == [],
                'Resource/application preservation audit failed: ' + name)
        require(len(audit['resources']) == 2 and {r['bank'] for r in audit['resources']} == {1, 2},
                'Incomplete bank readback audit')
        entries = [e for bank in audit['resources'] for e in bank['entries']]
        require(all(bank['all_defined_resource_bytes_exact'] is True and bank['preheader_byte_exact'] is True
                    and bank['directory_byte_exact'] is True for bank in audit['resources'])
                and len(entries) == 8 and {e['name'] for e in entries} == set(THEMES.values())
                and all(e['source_payload_byte_exact'] is True and e['stored_CRC32_valid'] is True for e in entries),
                'Installed/cold native resource readback failed')
    for name in ('installed_settings', 'cold_settings'):
        audit = data[name]
        require(audit['all_seven_databases_valid'] is True and audit['selected_WARMLIGHT_preserved'] is True
                and audit['unexpected_non_theme_setting_changes'] == []
                and audit['selected_HMI_theme'] == [11]
                and audit['native_Harmony_ini_hex'] == b'HARMONY=201\0'.hex(), 'Settings preservation failed: ' + name)
        require(audit['active_theme_flags'] == {f'Harm_{uid}': int(uid in THEMES) for uid in range(1, 13)}
                and all(audit['theme_names'].get(f'harmony{uid}') == theme for uid, theme in THEMES.items())
                and len(audit['preview_files_verified']) == 6, 'Cold/installed native theme catalogue incomplete')
    visual = data['visual']
    require(visual['all_eight_theme_names_visible_in_native_chooser'] is True
            and visual['selected_WARMLIGHT_preserved'] is True and visual['clean_shutdown'] is True
            and visual['source_installed_NAND_unchanged'] is True, 'Native cold UI verification incomplete')
    return data


def validate_backup(directory, minimum=None, exact=None):
    manifest_path = directory / 'copy-manifest.json'
    manifest = read_json(manifest_path)
    rows = manifest['files']
    require(manifest['USB_serial'] == SERIAL and manifest['read_only_mount'] is True
            and len({row['path'] for row in rows}) == len(rows), 'USB backup identity/manifest mismatch')
    require((minimum is None or len(rows) >= minimum) and (exact is None or len(rows) == exact),
            'USB backup file coverage incomplete')
    for row in rows:
        relative = Path(row['path'])
        require(not relative.is_absolute() and '..' not in relative.parts, 'Unsafe backup member')
        saved = safe_file(directory / 'files' / relative)
        require(saved.stat().st_size == row['bytes'] and sha(saved) == row['sha256'], 'Original USB backup changed')
    return manifest_path, rows


def validate_proofs(candidate, proof_path, backup, source_check_backup=SOURCE_CHECK_BACKUP):
    require(candidate.is_relative_to(ROOT / 'artifacts/phase20') and not candidate.is_symlink(),
            'Candidate must be an isolated Phase20 artifact directory')
    image = safe_file(candidate / 'usb.raw')
    meta, proof = read_json(candidate / 'usb.json'), read_json(proof_path)
    digest = sha(image)
    require(image.stat().st_size == IMAGE_BYTES
            and digest == meta['image_sha256'] == proof['candidate_USB_sha256'], 'Exact tested image changed')
    for field in ('single_USB_stock_to_eight_theme_install_and_cold_boot_verified',
                  'original_application_binary_byte_exact', 'selected_WARMLIGHT_preserved',
                  'all_seven_databases_integrity_INF_valid', 'native_progress_UI_verified',
                  'native_completion_UI_verified'):
        require(proof.get(field) is True, 'Missing verified behavior: ' + field)
    require(proof['unexpected_non_theme_setting_changes'] == [] and proof['critical_guest_failures'] == []
            and set(proof['verified_theme_names']) == set(THEMES.values()), 'Incomplete preservation/theme proof')
    require(proof.get('physical_car_compatibility_certified') is False
            and proof.get('physical_recovery_certified') is False, 'Do not claim physical recovery certification')
    require(isinstance(proof['known_cosmetic_limitations'], list), 'Known limitations must remain recorded')
    limitations = '\n'.join(proof['known_cosmetic_limitations']).lower()
    require('elliptic' in limitations and 'cubic' in limitations and 'clock' in limitations,
            'Retain existing ELLIPTIC/CUBIC clock-layout limitations')
    manifest_path = candidate / 'source-snapshot/manifest.json'
    closure = read_json(manifest_path)
    require(SOURCE_CLOSURE_MINIMUM <= closure.keys()
            and sha(manifest_path) == proof['source_snapshot_manifest_sha256']
            and {name: row['sha256'] for name, row in closure.items()} == proof['source_closure_sha256'],
            'Exact source closure not bound')
    for name, row in closure.items():
        require(Path(name).name == name, 'Unsafe source snapshot member')
        require(sha(safe_file(candidate / 'source-snapshot' / name)) == row['sha256'], 'Frozen source changed')
        source = artifact_path(row['source'])
        require(source.is_file() and not source.is_symlink() and source.resolve().is_relative_to(ROOT)
                and sha(source) == row['sha256'], 'Current source changed since testing: ' + str(source))
    require(meta['source_sha256'] == closure['usb_complete_themes_sandbox.c']['sha256'], 'Wrong entry source hash')
    evidence = proof.get('evidence', [])
    require(evidence and len({row['path'] for row in evidence}) == len(evidence), 'Bound proof evidence missing/duplicated')
    bound = {}
    for row in evidence:
        path = safe_file(artifact_path(row['path']))
        require(sha(path) == row['sha256'], 'Bound evidence changed: ' + str(path))
        bound[str(path.resolve())] = row['sha256']
    rebuild_path = candidate / 'source-snapshot/rebuild-proof.json'
    rebuild = read_json(rebuild_path)
    require(str(rebuild_path.resolve()) in bound
            and rebuild['source_files'] == len(closure)
            and rebuild['manifest_sha256'] == proof['source_snapshot_manifest_sha256']
            and rebuild['module_sha256'] == sha(candidate / 'theme_resources.out')
            and rebuild['frozen_source_rebuild_byte_exact'] is True,
            'Frozen source closure does not reproduce the exact tested module')
    payload_path = safe_file(artifact_path(proof['payload_physical_read_match']))
    faults_path = safe_file(artifact_path(proof['control_flow_fault_tests']))
    require(str(payload_path.resolve()) in bound and str(faults_path.resolve()) in bound,
            'Physical source-read match/control-flow evidence not bound')
    payload_match, faults = read_json(payload_path), read_json(faults_path)
    expected_data = [row for row in meta['files'] if not row['path'].startswith('FLYING/')]
    require(payload_match['all_ten_data_members_exact'] is True
            and payload_match['candidate_image_sha256'] == digest
            and sorted(payload_match['data_files'], key=lambda row: row['path'])
            == sorted(expected_data, key=lambda row: row['path']), 'Known physical source-read payloads differ')
    require(faults['all_tests_pass'] is True and faults['actual_production_control_flow_compiled'] is True
            and len(faults['cases']) >= 20 and all(row['passed'] is True for row in faults['cases']),
            'Native installer fault-control tests incomplete')
    for name, row in faults['production_sources'].items():
        filename = Path(name).name
        if filename in closure:
            require(row['sha256'] == closure[filename]['sha256'], 'Fault tests used different installer sources')
    audits = check_audits(proof, bound)
    native_run, cold_run = artifact_path(proof['native_run']), artifact_path(proof['cold_run'])
    for run in (native_run, cold_run):
        require(str((run / 'result.json').resolve()) in bound, 'Runtime result not bound')
    native_result, cold_result = read_json(native_run / 'result.json'), read_json(cold_run / 'result.json')
    require(native_result['returncode'] == 0 and native_result['wait_marker_seen'] is True
            and native_result['native_memory_requested'] is True and native_result['audio_256'] is True
            and native_result['emulated_RAM_MiB'] == 256
            and native_result['physical_device_access'] is False, 'Native USB test incomplete')
    require(cold_result['exit_code'] == 0 and cold_result['source_unchanged'] is True
            and cold_result['USB_attached'] is False and cold_result['guest_RAM_patches'] is False
            and cold_result['RSP_used'] is False and cold_result['serial_exception_lines'] == [], 'USB-free cold test failed')
    require(Path(cold_result['source']).resolve() == (native_run / 'nand.raw').resolve()
            and cold_result['source_sha256'] == audits['installed_resources']['NAND_sha256'], 'Cold run did not use installed NAND')
    require(sha(safe_file(native_run / 'nand.raw')) == audits['installed_resources']['NAND_sha256']
            and sha(safe_file(cold_run / 'nand.raw')) == audits['cold_resources']['NAND_sha256']
            == cold_result['stopped_nand_sha256'], 'Stopped installed/cold NAND evidence changed')
    rows = meta['files']
    require(len(rows) == 13 and {r['path'] for r in rows} == MEMBERS, 'Unexpected USB members')
    listing = mtool(image, 'mdir', '-b', '-/', '::/').decode().splitlines()
    names = {name.removeprefix('::/').casefold() for name in listing if name and not name.endswith('/')}
    require(names == {name.casefold() for name in MEMBERS}, 'Unexpected files retained in image')
    contents = {}
    for row in rows:
        value = mtool(image, 'mtype', '::/' + row['path'])
        require(len(value) == row['bytes'] and hashlib.sha256(value).hexdigest() == row['sha256'], 'USB member mismatch')
        require(mtool(native_run / 'usb.raw', 'mtype', '::/' + row['path']) == value,
                'Native test did not use this exact installer payload: ' + row['path'])
        contents[row['path']] = value
    module = contents['FLYING/theme_resources.out']
    require(module == safe_file(candidate / 'theme_resources.out').read_bytes(), 'Module differs from image')
    imports = audit_installer(module, meta)
    check_crc(module, contents['FLYING/theme_resources.out.inf'], 'native module')
    expected_doctor = b'0000\r\nACTION:TemporaryBootRom\r\nLOAD_AND_EXECUTE:/bd0/FLYING/theme_resources.out\r\n'
    doctor = contents['FLYING/doctor_smeg_plus_i.inf']
    require(doctor[4:] == expected_doctor and doctor[:4] == f'{crc16(expected_doctor):04x}'.encode(), 'Wrong native USB entry')
    banks = audit_banks(contents, candidate, meta)
    expected_sidecars = [dict(path=f'THEME_TEST/bank{bank}.bin.inf',
        bytes=len(contents[f'THEME_TEST/bank{bank}.bin.inf']),
        crc32=f'{zlib.crc32(contents[f"THEME_TEST/bank{bank}.bin.inf"]):08x}',
        sha256=hashlib.sha256(contents[f'THEME_TEST/bank{bank}.bin.inf']).hexdigest()) for bank in (1, 2)]
    require(meta.get('source_sidecar_files') == expected_sidecars, 'Sidecar preflight contract differs from image')
    sidecar_checks = check_sidecar_receipts(contents, native_run)
    complete = mtool(native_run / 'usb.raw', 'mtype', '::/SMEG_BACKUP/complete-themes.txt').decode()
    require(complete.splitlines()[-1] == 'COMPLETE_THEMES_RESULT status=0', 'Native complete installer failed')
    status = mtool(native_run / 'usb.raw', 'mtype', '::/THEME_STATUS.TXT').decode()
    require(status.splitlines()[0] == 'DONE', 'Native completion dialog/receipt did not succeed')
    # Preserve both the fresh current USB contents (the newer diagnostic was
    # never used in the car) and the independent earlier physical source test.
    backup_manifest_path, backup_rows = validate_backup(backup, minimum=13)
    source_manifest_path, _ = validate_backup(source_check_backup, exact=16)
    physical = read_json(source_check_backup / 'verification.json')
    require(physical['read_only_physical_test_passed'] is True
            and physical['both_bank_sources_two_full_matching_CRC_reads'] is True
            and physical['all_13_original_payload_files_unchanged'] is True, 'Prior source-read verification missing')
    return image, meta, proof, dict(
        verification=str(proof_path), verification_sha256=sha(proof_path),
        source_snapshot_manifest_sha256=sha(manifest_path), source_closure_sha256=proof['source_closure_sha256'],
        module_imports=imports, verified_banks=banks, pre_erase_INF_sidecars_verified=sidecar_checks,
        old_USB_file_backup=str(backup),
        old_USB_file_backup_manifest_sha256=sha(backup_manifest_path), old_USB_backup_files_verified=len(backup_rows),
        physical_read_only_source_backup=str(source_check_backup),
        physical_read_only_source_manifest_sha256=sha(source_manifest_path),
        physical_read_only_source_verification_sha256=sha(source_check_backup / 'verification.json'),
    )


def write_receipt(path, report):
    """Durable replacement within this invocation's new evidence directory."""
    with tempfile.NamedTemporaryFile('w', dir=path.parent, prefix='.receipt-', delete=False) as temp:
        json.dump(report, temp, indent=2)
        temp.write('\n')
        temp.flush()
        os.fsync(temp.fileno())
        temporary = Path(temp.name)
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--proof', type=Path, required=True)
    parser.add_argument('--backup', type=Path, required=True)
    parser.add_argument('--source-check-backup', type=Path, default=SOURCE_CHECK_BACKUP)
    parser.add_argument('--preparation', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--write', action='store_true')
    mode.add_argument('--local-only', action='store_true')
    args = parser.parse_args()
    require(not any(p.is_symlink() for p in (args.candidate, args.proof, args.backup, args.source_check_backup, args.preparation)), 'Symlink inputs refused')
    candidate, proof_path, backup, source_check_backup, preparation = (
        p.resolve() for p in (args.candidate, args.proof, args.backup, args.source_check_backup, args.preparation))
    require(backup.is_relative_to(ROOT / 'artifacts')
            and preparation.is_relative_to(ROOT / 'artifacts/phase21') and preparation.parent.is_dir(), 'Unsafe backup/output directory')
    image, meta, proof, checked = validate_proofs(candidate, proof_path, backup, source_check_backup)
    report = dict(
        created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), USB_serial=SERIAL,
        device=str(DEVICE), image=str(image), image_sha256=meta['image_sha256'], image_bytes=IMAGE_BYTES,
        USB_written=False, physical_car_accessed=False, experimental_native_theme_installer=True,
        physical_car_compatibility_certified=False, physical_recovery_certified=False,
        scope='Native theme banks/previews and six theme catalogue flags only; no OS/database replacement',
        theme_banks_rewritten=[1, 2], selected_WARMLIGHT_preserved_in_QEMU=True,
        custom_apps_or_network_changes=False, known_cosmetic_limitations=proof['known_cosmetic_limitations'],
        native_write_progress='Measured verification/readback bytes and labelled native blocking stages', **checked,
    )
    if args.local_only:
        print(json.dumps(report, indent=2))
        return
    device, mounted = device_state()
    report.update(resolved_device=device['path'], mounted=mounted)
    if not args.write:
        print(json.dumps(report, indent=2))
        return
    require(os.geteuid() == 0, 'Administrator authentication required')
    require(not mounted, 'Unmount the identified Verbatim USB first')
    require(not preparation.exists(), 'Preserve previous USB preparation history')
    with os.fdopen(os.open(image, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as source:
        validate_open_source(source, meta['image_sha256'], IMAGE_BYTES)
        device, mounted = device_state()
        require(not mounted, 'USB became mounted')
        fd = os.open(DEVICE, os.O_RDWR | os.O_EXCL)
        try:
            validate_open_device(fd, device)
            preparation.mkdir(mode=0o755)
            saved, receipt = preparation / 'original-prefix.raw', preparation / 'preparation.json'
            report['original_prefix_backup'] = str(saved)
            try:
                os.lseek(fd, 0, os.SEEK_SET)
                remaining, digest = IMAGE_BYTES, hashlib.sha256()
                with saved.open('xb') as stream:
                    while remaining:
                        value = os.read(fd, min(remaining, 8 << 20))
                        require(value, 'Short current USB prefix read')
                        require(stream.write(value) == len(value), 'Short host prefix backup write')
                        digest.update(value)
                        remaining -= len(value)
                    stream.flush()
                    os.fsync(stream.fileno())
                require(saved.stat().st_size == IMAGE_BYTES and sha(saved) == digest.hexdigest(), 'Current USB backup failed')
                report['original_prefix_sha256'] = verify_prefix(fd, IMAGE_BYTES, digest.hexdigest())
                report.update(original_prefix_backup_verified=True, phase='backup_verified_before_write')
                write_receipt(receipt, report)
                report['readback_sha256'] = replace_prefix(fd, source, IMAGE_BYTES, meta['image_sha256'])
                report.update(USB_written=True, readback_verified=True, phase='complete')
                fcntl.ioctl(fd, 0x125f)
            except BaseException as error:
                report.update(phase='failed_do_not_use_USB', error=repr(error))
                write_receipt(receipt, report)
                raise
            write_receipt(receipt, report)
        finally:
            os.close(fd)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
