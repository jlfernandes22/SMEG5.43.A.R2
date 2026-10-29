#!/usr/bin/env python3
"""Stage only the verified read-only verifier/UI probe on the known Verbatim.

Default: validate local evidence and inspect device identity without opening it.
--write: require root and an unmounted, exclusively opened identified USB; save
its current complete image prefix before writing and independently reading back
the tested prefix. Never accesses the physical car or installs theme resources.
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

from elftools.elf.elffile import ELFFile
from prepare_verified_theme_usb import (
    ROOT, DEVICE, SERIAL, require, device_state, validate_open_device,
    validate_open_source,
)
from prepare_warmlight_test_usb import verify_prefix, replace_prefix
from smeg_db_inf import crc16

BASE = ROOT / 'artifacts/phase21'
PROBE = BASE / 'retry-readonly-native-ui-v1'
ORIGINAL = BASE / 'physical-original-checker-return-2026-10-29'
PREPARATION = BASE / 'physical-retry-readonly-preparation-2026-10-29'
IMAGE_BYTES = 135266304
SOURCE_FILES = {
    'usb_theme_retry_readonly.c', 'theme_source_verify.h',
    'theme_install_progress.h', 'theme_progress_contract.h',
    'theme_resource_contract.h',
}
LIVE_SOURCE_FILES = {
    'usb_theme_retry_readonly.c', 'theme_source_verify.h',
    'theme_install_progress.h',
}
FLYING_FILES = {
    'FLYING/readcheck.out', 'FLYING/readcheck.out.inf',
    'FLYING/doctor_smeg_plus_i.inf',
}
ALLOWED_IMPORTS = {
    'fopen', 'fread', 'fprintf', 'snprintf', 'fflush', 'fclose', 'ferror',
    'errnoGet', 'taskDelay', 'sysClkRateGet',
}
READ_PRE_ADDRESS = 0x0025f068
# These must not be materialized or stored in the executable module. The
# copied input contract may describe the original installer, but it is data
# for compilation only, and the compiler must discard its unused writer rows.
FORBIDDEN_NATIVE_ADDRESSES = {
    0x0025ebf4, 0x0025ef38,  # WriteBigHarmony / EraseAllHarmonies.
    0x0025f468, 0x0025f554, 0x0025f6b4,  # No additional NAND API is needed.
}


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def safe_file(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink()
            and path.resolve().is_relative_to(ROOT), 'Unsafe evidence file: ' + str(path))
    return path


def json_file(path):
    return json.loads(safe_file(path).read_text())


def artifact_directory(path, *, must_exist=True):
    """Keep all selectable inputs/output receipts inside local artifacts."""
    path = Path(path).absolute()
    resolved = path.resolve()
    require(resolved.is_relative_to(ROOT / 'artifacts')
            and resolved != ROOT / 'artifacts', 'Expected workspace artifact directory')
    require(not path.is_symlink(), 'Symlink artifact directory refused')
    for parent in path.parents:
        if parent == ROOT:
            break
        require(not parent.is_symlink(), 'Symlink artifact parent refused')
    if must_exist:
        require(resolved.is_dir(), 'Artifact directory does not exist: ' + str(path))
    else:
        require(resolved.parent.is_dir(), 'Preparation parent directory does not exist')
    return resolved


def validate_original_backup(original):
    """Validate every returned USB file; the manifest determines its count."""
    manifest_path = original / 'copy-manifest.json'
    manifest = json_file(manifest_path)
    rows = manifest.get('files')
    require(manifest.get('USB_serial') == SERIAL and manifest.get('read_only_mount') is True
            and isinstance(rows, list) and rows, 'Original physical backup incomplete')
    names = set()
    for row in rows:
        require(isinstance(row, dict) and isinstance(row.get('path'), str),
                'Malformed backup manifest member')
        name = row['path']
        relative = Path(name)
        require(name and '\\' not in name and not relative.is_absolute()
                and all(part not in ('', '.', '..') for part in name.split('/')),
                'Unsafe backup member path')
        require(name.casefold() not in names, 'Duplicate backup manifest member')
        names.add(name.casefold())
        require(type(row.get('bytes')) is int and row['bytes'] >= 0
                and isinstance(row.get('sha256'), str)
                and re.fullmatch(r'[0-9a-f]{64}', row['sha256']) is not None,
                'Invalid backup member size/hash')
        file = safe_file(original / 'files' / relative)
        require(file.stat().st_size == row['bytes'] and sha(file) == row['sha256'],
                'Returned physical evidence changed: ' + str(relative))
    return manifest_path, len(rows)


def source_byte_progress(text):
    """Parse exact clean combined-run byte counters, logged after source close."""
    sizes = {}
    for bank, size in re.findall(
            r'SOURCE_CHECK path=/bd0/THEME_TEST/bank([12])\.bin attempt=\d+ opened=\d+ '
            r'bytes=\d+ expected_bytes=(\d+) ', text):
        bank, size = int(bank), int(size)
        require(size > 0 and (bank not in sizes or sizes[bank] == size),
                'Source size changed across attempts')
        sizes[bank] = size
    require(set(sizes) == {1, 2}, 'Both source bank sizes are required for progress')
    total = 2 * sum(sizes.values())
    rows = []
    previous = None
    for values in re.findall(r'^BYTE_PROGRESS bank=(\d+) attempt=(\d+) percent=(\d+) '
                             r'done=(\d+) total=(\d+)\r?$', text, re.M):
        bank, attempt, percent, done, count = map(int, values)
        require(bank in (1, 2) and 1 <= attempt <= 3 and count == total
                and 0 <= done <= total and percent == min(99, done * 100 // total),
                'Source byte progress counters disagree')
        require(previous is None or (percent > previous[0] and done > previous[1]),
                'Source byte progress is not increasing')
        rows.append(dict(bank=bank, attempt=attempt, percent=percent,
                         completed_bytes=done, total_bytes=count))
        previous = percent, done
    require(len(rows) >= 2, 'Source byte progress samples missing')
    return rows


def validate_progress_evidence(proof, bound_evidence=None, *, source_rows=None, run=None):
    """Require observed native fill movement backed by distinct image hashes."""
    require(proof.get('real_progress_verified') is True, 'Native progress not verified')
    rows = proof.get('progress_evidence')
    require(isinstance(rows, list) and len(rows) >= 2, 'Progress screenshots missing')
    seen = set()
    previous = None
    total = None
    bound = ({(str(Path(row['path']).resolve()), row['sha256']) for row in bound_evidence}
             if bound_evidence is not None else None)
    for row in rows:
        require(isinstance(row, dict), 'Malformed progress evidence')
        path = safe_file(row['screenshot']).resolve()
        digest = row.get('screenshot_sha256')
        require(sha(path) == digest and digest not in seen, 'Progress screenshot changed or duplicated')
        seen.add(digest)
        require(bound is None or (str(path), digest) in bound,
                'Progress screenshot is not bound by verification evidence')
        require(all(type(row.get(field)) is int for field in ('percent', 'completed_bytes', 'total_bytes')),
                'Progress counters must be integers')
        done, count, percent = row['completed_bytes'], row['total_bytes'], row['percent']
        require(count > 0 and 0 <= done <= count and 0 < percent < 100
                and percent == min(99, done * 100 // count), 'Progress counters disagree')
        require(total is None or total == count, 'Progress total changed')
        require(previous is None or (done > previous[0] and percent > previous[1]),
                'Progress fill did not increase')
        review = row.get('visual_review', {})
        require(review.get('reviewed') is True and review.get('native_progress_fill') is True,
                'Native progress screenshot not visually verified')
        if source_rows is not None:
            require(any((sample['percent'], sample['completed_bytes'], sample['total_bytes'])
                        == (percent, done, count) for sample in source_rows),
                    'Screenshot counters absent from native source-read trace')
        if run is not None:
            require(path.is_relative_to(run), 'Progress screenshot is outside the exact good run')
        previous = done, percent
        total = count
    return rows


def mtool(image, command, *args):
    return subprocess.check_output(
        [command, '-i', str(image) + '@@1048576', *args],
        env=dict(os.environ, MTOOLS_SKIP_CHECK='1'),
    )


def module_instructions(payload):
    """Use the system disassembler, including under pkexec's clean root env."""
    with tempfile.TemporaryDirectory(prefix='smeg-readonly-elf-audit-') as temporary:
        module = Path(temporary) / 'readcheck.out'
        module.write_bytes(payload)
        result = subprocess.run(
            ['/usr/bin/llvm-objdump', '-d', '--no-show-raw-insn', str(module)],
            check=True, capture_output=True, text=True, timeout=30,
            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'},
        )
    instructions = []
    for line in result.stdout.splitlines():
        match = re.match(r'^\s*[0-9a-fA-F]+:\s+([.\w+]+)(?:\s+(.*))?$', line)
        if match:
            mnemonic = match[1]
            operands = [part.strip() for part in (match[2] or '').split(',')]
            instructions.append((mnemonic, operands))
    require(instructions, 'System disassembler produced no PowerPC instructions')
    return instructions


def register_name(operand):
    """LLVM prints bare register numbers; accept r-prefixed spelling as well."""
    match = re.fullmatch(r'r?(\d+)', operand)
    if match and 0 <= int(match[1]) < 32:
        return 'r' + str(int(match[1]))
    return None


def audit_module(payload):
    """Reject writer symbols/imports, raw writer pointers and PPC address loads."""
    elf = ELFFile(io.BytesIO(payload))
    require(elf.elfclass == 32 and not elf.little_endian
            and elf['e_machine'] == 'EM_PPC' and elf['e_type'] == 'ET_REL',
            'Expected the tested big-endian PowerPC relocatable module')
    symbols = list(elf.get_section_by_name('.symtab').iter_symbols())
    imports = sorted(s.name for s in symbols if s.name and s['st_shndx'] == 'SHN_UNDEF')
    require(set(imports) <= ALLOWED_IMPORTS, 'Unexpected module imports: ' + repr(imports))
    entry = [s for s in symbols if s.name == 'smeg_theme_retry_readonly']
    require(len(entry) == 1 and entry[0]['st_value'] == 0
            and elf.get_section(entry[0]['st_shndx']).name == '.text', 'Wrong module entry')
    require(not any(re.search(r'(erase|writebank|writebigharmony|setconfig|setcommon|'
                              r'install_theme|complete_theme|set_theme_catalogue)', s.name, re.I)
                    for s in symbols), 'Persistent writer/setter symbol in read-only module')
    constants = set()
    for section in elf.iter_sections():
        if section['sh_type'] == 'SHT_NOBITS' or not section['sh_flags'] & 2:
            continue
        data = section.data()
        for address in FORBIDDEN_NATIVE_ADDRESSES:
            require(struct.pack('>I', address) not in data,
                    'Native erase/program pointer retained in module')
    high = {}
    for mnemonic, operands in module_instructions(payload):
        # clang materializes native constant function pointers with lis then
        # ori/addi. Inspect those instructions independently of ELF imports.
        if mnemonic == 'lis' and len(operands) == 2:
            dest = register_name(operands[0])
            require(dest is not None, 'Unrecognized disassembler register')
            high[dest] = (int(operands[1], 0) << 16) & 0xffffffff
        elif mnemonic in ('ori', 'addi') and len(operands) == 3:
            dest, source = register_name(operands[0]), register_name(operands[1])
            require(dest is not None and source is not None, 'Unrecognized disassembler register')
            if source in high:
                value = int(operands[2], 0)
                value = (high[source] | (value & 0xffff)) if mnemonic == 'ori' else high[source] + value
                value &= 0xffffffff
                constants.add(value)
                high[dest] = value
            else:
                high.pop(dest, None)
        elif mnemonic.startswith(('b', 'mtctr', 'mtlr')):
            if mnemonic.startswith('b'):
                for operand in operands:
                    try:
                        # Direct branch output can have an annotated symbol:
                        # "0x25ef38 <name>". Keep its numeric target.
                        target = int(operand.split()[0], 0) & 0xffffffff
                    except (ValueError, IndexError):
                        continue
                    if target in FORBIDDEN_NATIVE_ADDRESSES or target == READ_PRE_ADDRESS:
                        constants.add(target)
            # Do not propagate speculative register values across control
            # flow or function calls. Matching native loads precede mtctr.
            high.clear()
        elif operands:
            high.pop(register_name(operands[0]), None)
    require(not constants & FORBIDDEN_NATIVE_ADDRESSES,
            'Native erase/program address materialized by code')
    require(READ_PRE_ADDRESS in constants, 'Expected sole native NAND read entry missing')
    return imports


def validate_proofs(probe=PROBE, original=ORIGINAL):
    probe = artifact_directory(probe)
    original = artifact_directory(original)
    image = safe_file(probe / 'usb.raw')
    meta = json_file(probe / 'usb.json')
    proof = json_file(probe / 'verification.json')
    digest = sha(image)
    require(image.stat().st_size == IMAGE_BYTES
            and digest == meta['image_sha256'] == proof['image_sha256'], 'Tested image changed')
    for field in (
        'native_test_complete', 'both_bank_checks_pass', 'native_UI_success_verified',
        'native_UI_failure_verified', 'all_three_stock_application_and_theme_containers_exact',
        'all_seven_databases_valid', 'unrelated_preferences_unchanged',
    ):
        require(proof.get(field) is True, 'Incomplete verification: ' + field)
    require(proof.get('physical_car_tested') is False
            and proof.get('read_only_physical_test_only') is True,
            'Expected isolated read-only test evidence')
    require(meta.get('read_only_car_test') is True
            and meta.get('temporary_stock_UI_only') is True
            and meta.get('persistence_setters_included') is False
            and meta.get('NAND_erase_or_program_included') is False
            and meta.get('application_or_BSP_replacement') is False,
            'Wrong probe scope')
    sources = meta['source_sha256']
    require(set(sources) == SOURCE_FILES and proof.get('source_sha256') == sources,
            'Verification does not bind the exact source closure')
    for name, expected in sources.items():
        require(sha(safe_file(probe / name)) == expected, 'Copied source changed: ' + name)
        if name in LIVE_SOURCE_FILES:
            require(sha(safe_file(ROOT / 'emulation' / name)) == expected,
                    'Live source changed since test: ' + name)
    require(re.search(r'resource_api\[\]\s*=\s*\{\s*\{0x25f068u,',
                      (probe / 'theme_resource_contract.h').read_text()) is not None,
            'Wrong native read-preheader address')
    evidence = proof.get('evidence', [])
    require(evidence and len({r['path'] for r in evidence}) == len(evidence),
            'Bound verification evidence missing or duplicated')
    for row in evidence:
        path = Path(row['path'])
        if not path.is_absolute():
            path = ROOT / path
        require(sha(safe_file(path)) == row['sha256'], 'Verification evidence changed: ' + str(path))
    if meta.get('determinate_progress') is True:
        require(proof.get('native_source_byte_progress_verified') is True,
                'Native source-byte progress not verified')
        receipt = safe_file(probe / 'qemu-readchecks.txt')
        require((str(receipt.resolve()), sha(receipt)) in {
                    (str(Path(row['path']).resolve()), row['sha256']) for row in evidence},
                'Native source-byte receipt is not bound by verification evidence')
        progress = source_byte_progress(receipt.read_text())
        good_runs = [Path(folder).resolve() for folder, result in proof.get('runs', {}).items()
                     if result.get('expected_status') == 0]
        require(len(good_runs) == 1, 'Exact successful combined run missing')
        validate_progress_evidence(proof, evidence, source_rows=progress, run=good_runs[0])
    members = {row['path']: row for row in meta['files']}
    require(len(meta['files']) == 3 and set(members) == FLYING_FILES, 'Unexpected module payload members')
    listing = mtool(image, 'mdir', '-b', '::/FLYING').decode().splitlines()
    actual = {line.removeprefix('::/').casefold() for line in listing if line.strip()}
    require(actual == {name.casefold() for name in FLYING_FILES}, 'Unexpected executable directory contents')
    contents = {}
    for name, row in members.items():
        data = mtool(image, 'mtype', '::/' + name)
        require(len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256'],
                'Image member differs: ' + name)
        contents[name] = data
    module = contents['FLYING/readcheck.out']
    require(safe_file(probe / 'readcheck.out').read_bytes() == module, 'ELF differs from image')
    imports = audit_module(module)
    require(imports == meta['module_imports'], 'ELF imports differ from tested metadata')
    inf = contents['FLYING/readcheck.out.inf']
    doctor = contents['FLYING/doctor_smeg_plus_i.inf']
    require(inf[:4] == f'{crc16(inf[4:]):04x}'.encode()
            and inf[4:8] == f'{crc16(module):04x}'.encode(), 'Module INF CRC mismatch')
    expected_doctor = b'0000\r\nACTION:TemporaryBootRom\r\nLOAD_AND_EXECUTE:/bd0/FLYING/readcheck.out\r\n'
    require(doctor[4:] == expected_doctor
            and doctor[:4] == f'{crc16(expected_doctor):04x}'.encode(), 'Wrong USB execution entry')
    manifest_path, original_count = validate_original_backup(original)
    return image, meta, proof, dict(
        verification=str(probe / 'verification.json'), verification_sha256=sha(probe / 'verification.json'),
        module_imports=imports, source_sha256=sources, original_backup=str(original),
        original_backup_manifest_sha256=sha(manifest_path), original_backup_files_verified=original_count,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', type=Path, default=PROBE)
    parser.add_argument('--original-backup', type=Path, default=ORIGINAL)
    parser.add_argument('--preparation', type=Path, default=PREPARATION)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    preparation = artifact_directory(args.preparation, must_exist=False)
    image, meta, _, checked = validate_proofs(args.probe, args.original_backup)
    device, mounted = device_state()
    report = dict(
        created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        USB_serial=SERIAL, device=str(DEVICE), resolved_device=device['path'],
        image=str(image), image_bytes=IMAGE_BYTES, image_sha256=meta['image_sha256'],
        preparation=str(preparation),
        USB_written=False, read_only_car_diagnostic=True, theme_installer_removed=True,
        vehicle_setting_changes=False, physical_car_accessed=False,
        physical_car_compatibility_verified=False, mounted=mounted, **checked,
    )
    if not args.write:
        print(json.dumps(report, indent=2))
        return
    require(os.geteuid() == 0, 'Administrator access required')
    require(not mounted, 'Unmount the identified USB first')
    require(not preparation.exists(), 'Preserve prior preparation evidence; do not overwrite')
    # Hold the exact source before opening the physical USB. The helper also
    # checks the bytes again as they are written and reads the device back.
    with os.fdopen(os.open(image, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as source:
        validate_open_source(source, meta['image_sha256'], IMAGE_BYTES)
        device, mounted = device_state()
        require(not mounted, 'USB became mounted')
        fd = os.open(DEVICE, os.O_RDWR | os.O_EXCL)
        try:
            validate_open_device(fd, device)
            preparation.mkdir(mode=0o755)
            saved = preparation / 'original-prefix.raw'
            receipt = preparation / 'preparation.json'
            report['original_prefix_backup'] = str(saved)
            try:
                os.lseek(fd, 0, os.SEEK_SET)
                digest = hashlib.sha256()
                left = IMAGE_BYTES
                with saved.open('xb') as backup:
                    while left:
                        data = os.read(fd, min(left, 8 << 20))
                        require(data, 'Short USB prefix backup read')
                        require(backup.write(data) == len(data), 'Short host backup write')
                        digest.update(data)
                        left -= len(data)
                    backup.flush()
                    os.fsync(backup.fileno())
                require(sha(saved) == digest.hexdigest(), 'Original USB prefix backup failed')
                report['original_prefix_sha256'] = verify_prefix(fd, IMAGE_BYTES, digest.hexdigest())
                report['original_prefix_backup_verified'] = True
                report['phase'] = 'backup_verified_before_write'
                receipt.write_text(json.dumps(report, indent=2) + '\n')
                report['readback_sha256'] = replace_prefix(fd, source, IMAGE_BYTES, meta['image_sha256'])
                report.update(USB_written=True, readback_verified=True, phase='complete')
                fcntl.ioctl(fd, 0x125f)  # BLKRRPART after successful full prefix readback.
            except BaseException as error:
                report.update(phase='failed_do_not_use_USB', error=repr(error))
                receipt.write_text(json.dumps(report, indent=2) + '\n')
                raise
            receipt.write_text(json.dumps(report, indent=2) + '\n')
        finally:
            os.close(fd)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
