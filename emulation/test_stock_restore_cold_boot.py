#!/usr/bin/env python3
"""Cold-boot a private copy of a stopped, audited Phase14 stock-restored NAND.

No USB, SQL edits, offline injection, guest calls, RSP connection or RAM patches.
Screenshots require subsequent visual inspection; this tool never infers that an
Internet option is locked/unlocked from a screenshot filename.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import struct
import subprocess
import time

from run_usb_probe import QMP

ROOT = Path(__file__).resolve().parents[1]
PHASE = ROOT / 'artifacts/phase14'
PACKAGE = ROOT / 'artifacts/phase2/package/SMEG_PLUS_UPG'
BACKUP = ROOT / 'artifacts/live_car_backup/2026-10-27-native-usb/usb/SMEG_BACKUP'
NAND_BYTES = 553648128
STOCK = {
    'AUDIO_BT_256/AppBin/f_BigQuick.bin': 'c3f329c0d56c4a1726b097ccd55a0eaf44f6ece0a14018886d146b09e47ccfa2',
    'HARMONY/BigHarmony_4/BIG_HARMONY.bin': '50b767967a9d4ee83b183210a00f335ec85701829d06ca57d9e239d36d3bbfea',
    'HARMONY/BigHarmony_5/BIG_HARMONY.bin': '266ef132ede2b9c05c698f504d00911433f897aead811fba79bb79cbd407a8df',
}
SOURCE_HASHES = {
    **{str(PACKAGE / name): digest for name, digest in STOCK.items()},
    str(PACKAGE / 'BSP/SMEG_PLUS_256/vxWorks.bin'): 'e8aff17981ae5ba8c1574fba70ed747d32ae08badec932bfae38b7f6a4694110',
    str(ROOT / 'artifacts/phase2/applications/AUDIO_BT_256/app.bin'): '2ff81057b66d02daa9c4b9687f5407396425f81555b80d02feb6672aebb89925',
    str(ROOT / 'artifacts/phase2/applications/AUDIO_BT_256/app_segment2.bin'): '03537bef77bbc54c64003159a0bcd3c5770b216a0290f89ac3415ab974f714b8',
}
DATABASES = {'config_options.sqlite', 'diag_zi.sqlite', 'up_common.sqlite', 'up_config.sqlite',
             'up_user.sqlite', 'up_user_hmi.sqlite', 'version_history.sqlite'}
LIVE_SITES = {0x0227f7b4: 0x409e0010, 0x04c171bc: 0x7c630034,
              0x0182d1e0: 0x981d00ba, 0x0182d4b8: 0x981d00ba}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def expected_harmony_regions(relative):
    source = PACKAGE / relative
    data = source.read_bytes()
    fields = dict(line.split(':', 1) for line in Path(str(source) + '.inf').read_text().replace('\\n', '\n').splitlines() if ':' in line)
    header = bytearray(168)
    for offset, value in ((0, 'BIGHARMONY'), (32, '0.540.0'),
                          (64, fields['VERSION_BIGHARMONY_STRUCT']),
                          (96, fields['DATE']), (128, fields['VERSION'])):
        encoded = value.encode('ascii')
        require(len(encoded) < 32, 'Invalid stock native Harmony metadata')
        header[offset:offset + len(encoded)] = encoded
    struct.pack_into('>II', header, 160, int(fields['HEADER_SIZE']), int(fields['HEADER_CRC32']) & 0xffffffff)
    return {'metadata': {'offset': 0, 'length': 168, 'sha256': hashlib.sha256(header).hexdigest()},
            'body': {'offset': 2048, 'length': len(data) - 2048, 'sha256': hashlib.sha256(data[2048:]).hexdigest()}}


def defined_harmony_match(item):
    """Accept defined native ranges only; never relabel padding as byte-exact."""
    if not item['path'].startswith('HARMONY/'):
        return False
    expected = expected_harmony_regions(item['path'])
    for match in item.get('matches', []):
        if match.get('native_defined_regions_match') is not True:
            continue
        regions = match.get('native_defined_regions', {})
        padding = regions.get('padding', {})
        if not (padding.get('offset') == 168 and padding.get('length') == 1880 and padding.get('indeterminate') is True):
            continue
        if all(regions.get(name, {}).get('offset') == target['offset'] and
               regions.get(name, {}).get('length') == target['length'] and
               regions.get(name, {}).get('actual_sha256') == target['sha256'] and
               regions.get(name, {}).get('expected_sha256') == target['sha256']
               for name, target in expected.items()):
            return True
    return False


def regular_phase14(path):
    path = Path(path)
    require(not path.is_symlink(), 'Symlinks are not accepted: ' + str(path))
    resolved = path.resolve(strict=True)
    require(resolved.is_relative_to(PHASE), 'Only existing Phase14 regular files are accepted')
    require(stat.S_ISREG(resolved.stat().st_mode), 'Block devices and special files are forbidden')
    return resolved


def validate_audit(audit, source, source_sha):
    require((ROOT / audit.get('nand', '')).resolve() == source, 'Audit NAND path mismatch')
    require(audit.get('nand_sha256', audit.get('source_nand_sha256')) == source_sha,
            'Audit must bind the exact stopped NAND SHA256 (nand_sha256)')
    require(audit.get('all_seven_database_contents_verified') is True,
            'All seven original database contents must be verified')
    full_bytes = audit.get('all_three_raw_container_bytes_verified') is True
    defined_regions = audit.get('all_three_raw_container_defined_regions_verified') is True
    require(full_bytes or defined_regions, 'All three native raw payloads must be verified')
    require(audit.get('stored_candidate_bytes_and_databases_verified') is True or
            (defined_regions and audit.get('stored_defined_payload_regions_and_databases_verified') is True),
            'Stored state audit is not successful')
    raw = audit.get('raw_containers', [])
    require(len(raw) == 3 and {x.get('path') for x in raw} == set(STOCK), 'Expected exactly three stock raw records')
    for item in raw:
        require(item.get('source_sha256') == STOCK[item['path']], 'Raw source is not the original stock payload')
        exact = any(m.get('exact_payload_match') is True and
                    m.get('sha256') == item.get('expected_stored_sha256')
                    for m in item.get('matches', []))
        require(exact or not full_bytes, 'Inconsistent audit claims full bytes while a container differs')
        require(exact or (defined_regions and defined_harmony_match(item)),
                'Missing exact native stored payload match or proven Harmony defined-range match')
    dbs = audit.get('databases', [])
    require(len(dbs) == 7 and {x.get('name') for x in dbs} == DATABASES, 'Expected exactly seven original databases')
    for item in dbs:
        require(item.get('present') is True and item.get('native_INF_valid') is True and
                item.get('sqlite_integrity') == 'ok' and item.get('expected_database_contents_match') is True,
                'Invalid stored database record: ' + str(item.get('name')))
        expected = (ROOT / item.get('expected_source', '')).resolve()
        require(expected == (BACKUP / item['name']).resolve(), 'Database expected source is not original car backup')


def no_source_writer(source):
    """Reject source NAND held open by any visible process, conservatively."""
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit() or int(proc.name) == os.getpid():
            continue
        try:
            for fd in (proc / 'fd').iterdir():
                try:
                    if fd.resolve() == source:
                        raise ValueError('Source NAND is still open by process ' + proc.name)
                except (FileNotFoundError, PermissionError):
                    pass
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            pass


def parse_hmp_word(reply):
    found = re.search(r':\s*(?:0x)?([0-9a-fA-F]{8})\b', reply)
    require(found is not None, 'Unrecognized read-only HMP memory response')
    return int(found.group(1), 16)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--nand', type=Path, required=True)
    p.add_argument('--native-source-audit', type=Path, required=True)
    p.add_argument('--stopped-prefix', required=True)
    p.add_argument('--tag', required=True)
    p.add_argument('--boot-seconds', type=int, default=150)
    p.add_argument('--key-variant-a1', action='store_true')
    p.add_argument('--check-only', action='store_true', help='Validate original sources/stopped NAND/audit without launching or copying')
    a = p.parse_args()
    require(re.fullmatch(r'[A-Za-z0-9]+', a.tag) is not None, 'Tag must be alphanumeric')
    require(100 <= a.boot_seconds <= 180, 'Boot wait must be 100..180 seconds')
    require(re.fullmatch(r'/tmp/smeg-[A-Za-z0-9_-]+', a.stopped_prefix) is not None, 'Invalid stopped runtime prefix')
    require(not any(Path(a.stopped_prefix + ext).exists() for ext in ('.qmp', '.gdb', '.monitor')),
            'Source runtime sockets still exist; source emulator must be stopped')
    source = regular_phase14(a.nand)
    audit_path = regular_phase14(a.native_source_audit)
    require(source.stat().st_size == NAND_BYTES, 'Expected 512MiB NAND with 2048+64 byte pages')
    no_source_writer(source)
    # This shared POSIX lock also refuses a conflicting QEMU image write lock.
    with source.open('rb') as lock:
        fcntl.lockf(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        source_sha = digest(source)
        audit = json.loads(audit_path.read_text())
        validate_audit(audit, source, source_sha)
        for name, expected in SOURCE_HASHES.items():
            require(digest(name) == expected, 'Original source fingerprint mismatch: ' + name)
        if a.check_only:
            print(json.dumps({'offline_guards_passed': True, 'nand_sha256': source_sha,
                              'native_source_audit_sha256': digest(audit_path), 'VM_started': False}))
            return
        out = PHASE / 'stock-restore' / ('cold-' + a.tag)
        out.mkdir(exist_ok=False)
        private = out / 'nand.raw'
        subprocess.run(['cp', '--reflink=auto', '--', str(source), str(private)], check=True)
        require(digest(private) == source_sha, 'Private copy differs before first boot')
        prefix = '/tmp/smeg-p14-stock-' + a.tag
        require(not any(Path(prefix + ext).exists() for ext in ('.qmp', '.gdb', '.monitor')), 'Cold runtime prefix already exists')
        env = {k: v for k, v in os.environ.items() if not k.startswith('SMEG_')}
        env.update(SMEG_NAND=str(private), SMEG_DISPLAY='none', SMEG_PIN_THREADS='0',
                   SMEG_CONTROL_PREFIX=prefix, SMEG_SERIAL='file:' + str(out / 'serial.log'),
                   SMEG_WINDOW_LOG=str(out / 'window.log'), SMEG_BENCH_ECU='1',
                   SMEG_BENCH_VEHICLE='1', SMEG_BENCH_KEY_PROFILE='1', LP_NUM_THREADS='2',
                   SMEG_KERNEL=str(PACKAGE / 'BSP/SMEG_PLUS_256/vxWorks.bin'),
                   SMEG_APP_VARIANT='audio_bt', SMEG_BSP_VARIANT='256',
                   SMEG_BENCH_HW_PROFILE='int_e', SMEG_FAST_MEM='1', SMEG_RAM_SIZE='512M')
        if a.key_variant_a1:
            env['SMEG_BENCH_KEY_VARIANT'] = 'a1'
        result = {'source_nand': str(source), 'source_sha256_before': source_sha,
                  'source_native_audit': str(audit_path), 'source_native_audit_sha256': digest(audit_path),
                  'source_native_stored_stock_payloads_verified': True,
                  'source_all_raw_full_bytes_equal': audit.get('all_three_raw_container_bytes_verified') is True,
                  'source_all_native_defined_regions_equal': audit.get('all_three_raw_container_defined_regions_verified') is True,
                  'native_Harmony_padding_scope': 'Offsets168..2047 may contain native heap residue; independently checked defined header0..167 and full body2048..end if audit uses defined-region mode',
                  'private_nand': str(private), 'private_sha256_before': source_sha,
                  'original_source_sha256': SOURCE_HASHES, 'emulated_RAM_MiB': 512,
                  'physical_device_access': False, 'USB_attached': False, 'SD_attached': False,
                  'guest_RAM_patches': False, 'RSP_observer_used': False, 'SQL_changes': False,
                  'offline_injection': False, 'screenshots': [], 'visual_verification_required': True,
                  'Internet_locked_or_unlocked_verified': False,
                  'bootstrap_limit': 'External unmodified BSP256 kernel; physical U-Boot/recovery not tested',
                  'boot_seconds': a.boot_seconds, 'qmp_prefix': prefix, 'environment': env}
        # Do not save unrelated inherited environment values (tokens etc.).
        result['environment'] = {k: v for k, v in env.items() if k.startswith('SMEG_') or k == 'LP_NUM_THREADS'}
        proc = None

        def command(name, args=None):
            q = QMP(prefix + '.qmp')
            try:
                return q.call(name, args)
            finally:
                q.close()

        def wait(seconds):
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise RuntimeError('Cold emulator exited before verification')
                time.sleep(min(.1, max(0, deadline - time.monotonic())))

        def screenshot(name):
            path = out / (name + '.png')
            command('screendump', {'filename': str(path), 'format': 'png'})
            result['screenshots'].append({'path': str(path), 'sha256': digest(path)})

        try:
            proc = subprocess.Popen(['bash', 'emulation/launch_ui.sh', '-D', str(out / 'qemu.log')],
                                    cwd=ROOT, env=env, start_new_session=True)
            deadline = time.monotonic() + 20
            while not Path(prefix + '.qmp').exists():
                require(proc.poll() is None and time.monotonic() < deadline, 'Cold QMP startup failed')
                time.sleep(.1)
            wait(a.boot_seconds)
            screenshot('radio-before-menu')
            live = []
            for address, expected in LIVE_SITES.items():
                reply = command('human-monitor-command', {'command-line': 'xp /1wx ' + hex(address)})
                value = parse_hmp_word(reply)
                live.append({'address': hex(address), 'expected': hex(expected), 'actual': hex(value), 'matches': value == expected})
            result['read_only_live_stock_instructions'] = live
            require(all(x['matches'] for x in live), 'Live application does not match original stock instructions')
            variant = command('qom-get', {'path': '/machine', 'property': 'frontpanel-key-variant'})
            result['frontpanel_key_variant'] = variant
            key = 1 if variant == 0xa1 else 0
            for state in (1, 2):
                command('qom-set', {'path': '/machine', 'property': 'frontpanel-event', 'value': (key << 8) | state})
                if state == 1:
                    wait(.15)
            menu_release = time.monotonic()
            wait(.25)
            screenshot('normal-menu')
            result['menu_release_to_screenshot_seconds'] = time.monotonic() - menu_release
            result['menu_capture_within_0_75_seconds'] = result['menu_release_to_screenshot_seconds'] <= .75
            result['guest_status'] = command('query-status')
            result['capture_completed'] = True
        except Exception as error:
            result['error'] = repr(error)
        finally:
            if proc is not None:
                if proc.poll() is None:
                    try:
                        command('quit')
                    except (OSError, EOFError, RuntimeError, ValueError) as error:
                        result['quit_error'] = repr(error)
                try:
                    proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGTERM)
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        os.killpg(proc.pid, signal.SIGKILL)
                        proc.wait(timeout=5)
                result['exit_code'] = proc.returncode
            serial = out / 'serial.log'
            result['serial_exception_lines'] = [line for line in serial.read_text(errors='replace').splitlines()
                if any(s in line.lower() for s in ('data access exception', 'task is suspended',
                                                   'unhandled exception', 'program exception', 'machine check'))] if serial.exists() else []
            result['source_sha256_after'] = digest(source)
            result['source_unchanged'] = result['source_sha256_after'] == source_sha
            result['private_sha256_after'] = digest(private)
            result['original_sources_unchanged'] = all(digest(name) == expected for name, expected in SOURCE_HASHES.items())
            result['automated_checks_passed'] = bool(result.get('capture_completed') and result['source_unchanged'] and
                result['original_sources_unchanged'] and not result['serial_exception_lines'] and
                result.get('menu_capture_within_0_75_seconds'))
            (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
            print(json.dumps(result), flush=True)
        if not result['automated_checks_passed']:
            raise SystemExit(1)


if __name__ == '__main__':
    main()
