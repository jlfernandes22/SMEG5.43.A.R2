#!/usr/bin/env python3
"""Fault-inject exact production installer/wrapper C with in-memory host I/O.

No devices, VM, native firmware execution or physical-car access. The production
sources are copied byte-for-byte into a private fixture; only their dependency
contracts, filesystem, native NAND APIs and publication APIs are replaced.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CASES = {
    0: 'clean', 1: 'native_erase_failure', 2: 'native_bank2_write_failure',
    3: 'native_bank1_write_failure', 4: 'bank2_preheader_read_failure',
    5: 'bank1_preheader_read_failure', 6: 'bank2_payload_CRC_mismatch',
    7: 'bank1_payload_read_failure', 8: 'bank2_big_header_failure',
    9: 'post_erase_UI_failure', 10: 'post_erase_log_open_failure',
    11: 'post_erase_log_flush_failure', 12: 'post_erase_log_close_failure',
    13: 'corrupt_source_before_erase', 14: 'BSP_fingerprint_mismatch_before_erase',
    15: 'post_erase_log_ferror', 16: 'post_erase_progress_log_open_failure',
    17: 'erase_write_and_receipt_failure_first_error_retained',
    18: 'both_native_writers_fail_first_error_retained',
    19: 'UI_failure_after_resources_before_publication',
    20: 'missing_native_sidecar_before_erase',
    21: 'corrupt_native_sidecar_before_erase',
}

def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    assert out.is_relative_to(ROOT / 'artifacts/phase22') and not out.exists()
    out.mkdir()
    sources = {}
    for relative in ['emulation/usb_complete_themes_sandbox.c',
                     'emulation/usb_install_theme_resources_sandbox.c',
                     'emulation/theme_source_verify.h',
                     'scripts/theme_installer_failure_harness.c']:
        original = ROOT / relative
        data = original.read_bytes()
        (out / original.name).write_bytes(data)
        sources[relative] = {'sha256': sha(data), 'bytes': len(data)}
    table = []
    for value in range(256):
        for _ in range(8):
            value = (value >> 1) ^ (0xedb88320 if value & 1 else 0)
        table.append(value)
    contract = '''#include <stdint.h>
struct ResourceAPI {uintptr_t address;unsigned bytes,hash;};
static struct ResourceAPI resource_api[6];
static unsigned original_pre_hash[2];
struct ResourceFile {unsigned bank;const char*path;unsigned bytes,crc32,pre_hash,big_hash,count,entry_hash[4];};
static struct ResourceFile resource_files[2];
struct ResourceInfFile {const char*path;unsigned bytes,crc32;};
static struct ResourceInfFile resource_inf_files[2];
#define RESOURCE_COUNT 2u
#define RESOURCE_INF_COUNT 2u
#define RESOURCE_ERASE_ALL 1
#define RESOURCE_COMPLETE_READBACK 1
#define RESOURCE_READ_API 5
#define RESOURCE_MAX_PAYLOAD_BYTES 64u
static const unsigned resource_crc_table[256]={''' + ','.join(f'0x{x:x}u' for x in table) + '};\n'
    (out / 'theme_resource_contract.h').write_text(contract)
    (out / 'usb_backup_readonly.c').write_text('/* Mock: outer USB backup/export entry is outside this control-flow test. */\n')
    (out / 'usb_theme_previews_sandbox.c').write_text('''
struct FixtureAPI {uintptr_t address;unsigned bytes,hash;};
static struct FixtureAPI warm_api_checks[10],preview_fs_api[2];
struct ThemePreview {const char*source;unsigned bytes,hash;};
static struct ThemePreview theme_previews[6];
static const char *preview_paths[6]={"/bd0/PREVIEWS/theme1.jpg","/bd0/PREVIEWS/theme2.jpg","/bd0/PREVIEWS/theme3.jpg","/bd0/PREVIEWS/theme4.jpg","/bd0/PREVIEWS/theme7.jpg","/bd0/PREVIEWS/theme8.jpg"};
static unsigned char buffer[8192];
static unsigned fingerprint(const void*p,unsigned n){return fnv(p,n);}
static int smeg_copy_new_theme_previews(void){publication++;event('P');return 0;}
static int smeg_emulator_extra_theme_flags(void){publication++;event('F');return 0;}
''')
    (out / 'usb_set_theme_catalogue_sandbox.c').write_text('''
static struct FixtureAPI common_api[13],common_bsp[2];
static unsigned common_catalogue_hash(const void*p,unsigned n){return fnv(p,n);}
static int smeg_set_theme_catalogue(void){publication++;event('C');return 0;}
''')
    (out / 'usb_refresh_theme_catalogue_sandbox.c').write_text('''
static int smeg_check_theme_cache_marker(void){return 0;}
static int smeg_refresh_theme_catalogue(void){publication++;event('M');return 0;}
''')
    (out / 'theme_install_progress.h').write_text('''
/* Native UI calls are mocked; production complete_progress_* bookkeeping is compiled. */
static int theme_progress_begin(void){return 0;}
static int theme_progress_step(const char*message){return test_progress(message);}
static int theme_progress_percent(unsigned percent){(void)percent;return test_progress("percent");}
static int theme_progress_detail(const char*message){return test_progress(message);}
static int theme_progress_finish(int status,const char*message){(void)status;(void)message;return 0;}
''')
    binary = out / 'host-installer-faults'
    command = ['clang', '-std=c11', '-O1', '-g', '-fno-omit-frame-pointer',
               '-fsanitize=address,undefined', '-Wall', '-Wextra', '-Werror',
               '-Wno-misleading-indentation', str(out / 'theme_installer_failure_harness.c'),
               '-o', str(binary)]
    build = subprocess.run(command, text=True, capture_output=True)
    (out / 'compile.log').write_text(build.stdout + build.stderr)
    assert build.returncode == 0, build.stderr
    results = []
    environment = dict(os.environ, ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    for case, name in CASES.items():
        run = subprocess.run([str(binary), str(case)], text=True, capture_output=True,
                             env=environment, timeout=20)
        (out / f'{case:02d}-{name}.log').write_text(run.stdout + run.stderr)
        assert run.returncode == 0, (name, run.returncode, run.stderr)
        result = json.loads(run.stdout)
        checks = {'no_source_or_native_IO_with_log_left_open': result['bad_overlap'] == 0}
        if case in (13, 14, 20, 21):
            checks.update(preflight_failure_did_not_erase=result['erased'] == 0,
                          preflight_failure_did_not_write=result['writes'] == [])
        else:
            checks['both_writers_attempted_bank2_then_bank1'] = result['writes'] == [2, 1]
            checks['both_writes_before_any_readback'] = (
                result['events'].startswith('E21') and
                result['events'].find('1') < min(
                    (result['events'].find(c) for c in ('r', 's') if c in result['events']),
                    default=999))
            checks['both_bank_readbacks_attempted'] = set(result['reads']) == {1, 2}
        if case == 0:
            checks.update(clean_success=result['status'] == 0,
                          publication_after_verified_resources=result['publication'] == 4)
        else:
            checks.update(fault_returns_failure=result['status'] != 0,
                          fault_blocks_flags_and_catalogue=result['publication'] == 0)
        if case in (9, 19):
            checks['UI_fault_was_reached'] = result['ui_failure_seen'] == 1
        if case in (1, 2, 3, 17, 18):
            checks['first_native_error_retained'] = result['status'] == {
                1: -205, 2: -202, 3: -201, 17: -205, 18: -202}[case]
        result.update(name=name, checks=checks, passed=all(checks.values()))
        results.append(result)
    report = dict(all_tests_pass=all(row['passed'] for row in results),
                  actual_production_control_flow_compiled=True,
                  production_sources=sources, compiler_command=command,
                  fixture_files={p.name: sha(p.read_bytes()) for p in out.iterdir()
                                 if p.suffix in ('.c', '.h')},
                  physical_device_access=False, QEMU_access=False,
                  sanitizer='ASAN+UBSAN; LeakSanitizer disabled for sandbox ptrace compatibility',
                  limitations=['Host ABI fixtures do not prove physical NAND behavior or PowerPC ABI.',
                               'Native NAND calls and later preview/configuration setters are mocked.',
                               'No power-loss recovery or hardware watchdog behavior is modeled.'],
                  cases=results)
    (out / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(all_tests_pass=report['all_tests_pass'], cases=len(results),
                         failures=[row['name'] for row in results if not row['passed']],
                         report=str(out / 'results.json'))))
    raise SystemExit(0 if report['all_tests_pass'] else 1)

if __name__ == '__main__':
    main()
