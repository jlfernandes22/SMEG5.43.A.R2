#!/usr/bin/env python3
"""Stage original extracted files and explicitly labelled default SQLite seeds.

Does not alter firmware, create launch scripts, or claim these are installed-unit
contents. Existing stage files must already match their source byte-for-byte.
"""
import argparse
import hashlib
import json
import re
import shutil
import sqlite3
from pathlib import Path


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--filesystems', type=Path, default=Path('artifacts/phase2/filesystems'))
    ap.add_argument('--package', type=Path, default=Path('artifacts/phase2/package/SMEG_PLUS_UPG'))
    ap.add_argument('--variant', choices=['NAV', 'AUDIO_BT', 'AUDIO_BT_256'], default='NAV')
    ap.add_argument('--output', type=Path, default=Path('artifacts/phase3/payloads'))
    ap.add_argument('--no-userdata-seeds', action='store_true')
    args = ap.parse_args()
    source = args.filesystems / args.variant
    manifest = {'variant': args.variant, 'generated_initial_state': True,
                'source_kind': 'Original update payload files; not a physical unit readback',
                'files': [], 'volumes': {}, 'assumptions': [],
                'native_loader': {'path': '/SYSTEM_DATA/ssm_boot.out',
                    'format': 'ELF32 PowerPC big-endian ET_REL',
                    'elf_entry_section_offset': '0x13aa8', 'entry_symbol': '_Z8SSM_Bootv',
                    'kernel_function': '_Z16LoadAndLaunchSSMPKc',
                    'kernel_function_address_512': '0x299270',
                    'startup_script_created': False}}
    container = args.package / args.variant / 'AppBin/f_BigQuick.bin'
    if container.is_file():
        span = 0x129 * 64 * 2048
        if container.stat().st_size > span:
            raise ValueError('application container exceeds kernel BigQuick area')
        manifest['raw_flash_sources'] = [{
            'source': str(container), 'bytes': container.stat().st_size,
            'sha256': sha(container), 'logical_byte_offset': 0x014a0000,
            'first_page': 0x2940, 'page_bytes': 2048,
            'reserved_erase_blocks': 0x129, 'erase_block_bytes': 0x20000,
            'reserved_bytes': span, 'end_exclusive': 0x039c0000,
            'format': 'original complete f_BigQuick.bin container, not decompressed app.bin',
            'placement_evidence': {
                'kernel_WriteNANDBigQuick': '0x25184c',
                'write_call_args_at_0x2518e4': ['path', 'first_page=0x2940', 'erase_blocks=0x129'],
                'erase_loop_0x245cec_to_0x245d00': 'page=first_page+(block_index<<6), calls nandBlockErase',
                'SSM_load_MetaHeader_call': 'ssm_boot.out .text0x13618..0x1362c calls ReadNand_area(1,g_header_bigquick,0,0x40)',
                'kernel_ReadNand_area': '0x247ab8; jump table0x71fd70 area1->0x247b54 loads0x014a0000',
                'header_check': 'SSM compares initial word to0x00010004'}}]

    def copy(src, volume, relative, kind):
        dst = args.output / volume / relative
        digest = sha(src)
        if dst.exists():
            if not dst.is_file() or sha(dst) != digest:
                raise ValueError('refusing to replace different stage file: ' + str(dst))
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)
        if sha(dst) != digest:
            raise ValueError('stage copy verification failed: ' + str(dst))
        manifest['files'].append({'source': str(src), 'destination': '/' + volume + '/' + str(relative),
                                  'bytes': src.stat().st_size, 'sha256': digest, 'kind': kind})

    for volume, directory in [('SYSTEM', 'system'), ('SYSTEM_DATA', 'system_data')]:
        tree = source / directory
        if not tree.is_dir():
            raise ValueError('missing extracted source: ' + str(tree))
        for src in sorted(tree.rglob('*')):
            if src.is_symlink():
                raise ValueError('unexpected source symlink: ' + str(src))
            if src.is_file():
                copy(src, volume, src.relative_to(tree), 'original_update_file')

    # Native BootROM checks both filenames with open(O_RDONLY), closing each
    # immediately. This is a boot-state presence marker, not an executable script.
    marker = args.output / 'SYSTEM_DATA/startApp.txt'
    if marker.exists():
        if not marker.is_file() or marker.read_bytes() != b'':
            raise ValueError('refusing to replace nonempty startup marker: ' + str(marker))
    else:
        marker.write_bytes(b'')
    manifest['files'].append({'source': 'generated: native BootROM presence marker',
        'destination': '/SYSTEM_DATA/startApp.txt', 'bytes': 0,
        'sha256': sha(marker), 'kind': 'generated_boot_state_presence_marker'})
    manifest['startup_marker_evidence'] = {
        'path': '/SYSTEM_DATA/startApp.txt', 'contents': '',
        'source': 'SMEG_PLUS_512/vxWorks.bin original instructions',
        'ssm_path_string_address': '0x7954ec',
        'marker_path_string_address': '0x795508',
        'ssm_open_call': '0x29a1e8', 'ssm_open_failure_branch': '0x29a1f0',
        'marker_open_call': '0x29a208', 'marker_open_failure_branch': '0x29a210',
        'failure_target': '0x29a23c', 'marker_close_call': '0x29a214',
        'success_return': '0x29a218',
        'semantics': 'Both files must open O_RDONLY. Marker is closed without reading its contents; empty presence marker is sufficient for this native check.',
        'error_string_typo': 'Message says starApp.txt; actual path literal is startApp.txt.'}
    harmony_ini = args.output / 'SYSTEM_DATA/HARMONY.INI'
    if harmony_ini.is_file():
        content = harmony_ini.read_bytes()
        if not re.fullmatch(rb'HARMONY=[0-9]{3}\0', content):
            raise ValueError('existing HARMONY.INI does not match recovered native writer format')
        manifest['files'].append({'source': 'generated: native skin configuration via emulation/seed_harmony.py',
            'destination': '/SYSTEM_DATA/HARMONY.INI', 'bytes': len(content),
            'sha256': sha(harmony_ini), 'kind': 'generated_native_skin_selection',
            'evidence': 'Application SaveSkinInHarmonyIniFile0x015c5a08 writes12bytes of HARMONY=<skin> plus NUL; SSM atoi(first_line+8).',
            'content_hex': content.hex()})

    for volume in ['USER_DATA', 'USER_DATA_BACKUP', 'SYSTEM_TMP_DATA', 'EXTENDED_PARTITION']:
        (args.output / volume).mkdir(parents=True, exist_ok=True)
    for relative in ['sqlite', 'Spy']:
        (args.output / 'SYSTEM_TMP_DATA' / relative).mkdir(parents=True, exist_ok=True)
    manifest['generated_directories'] = [
        {'path': '/SYSTEM_TMP_DATA/sqlite', 'evidence': 'Native application SQLite14 CANTOPEN on /SYSTEM_TMP_DATA/sqlite/up_common.sqlite and up_user_hmi.sqlite in app01.serial.log.'},
        {'path': '/SYSTEM_TMP_DATA/Spy', 'evidence': 'Original NAV application contains /SYSTEM_TMP_DATA/Spy/log_error.txt and /SYSTEM_TMP_DATA/Spy path literals.'}]
    if not args.no_userdata_seeds:
        manifest['assumptions'].append('USER_DATA/user_data/sqlite is initialized from the 29 original SYSTEM default databases. This is generated emulator initial state, not installed vehicle settings.')
        for src in sorted((source / 'system/Data_base/sqlite').glob('*.sqlite')):
            with sqlite3.connect(src.resolve().as_uri() + '?mode=ro&immutable=1', uri=True) as conn:
                conn.execute('PRAGMA query_only=ON')
                if conn.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                    raise ValueError('invalid seed SQLite: ' + str(src))
            copy(src, 'USER_DATA', Path('user_data/sqlite') / src.name, 'copied_default_seed_for_generated_initial_state')
    manifest['assumptions'].append('HARMONY.INI is included only when generated by the recovered native writer format; physical vehicle skin choice is unknown. Raw application/harmony placement is separate from these FAT-volume source trees.')
    for volume in ['SYSTEM', 'SYSTEM_DATA', 'USER_DATA', 'USER_DATA_BACKUP', 'SYSTEM_TMP_DATA', 'EXTENDED_PARTITION']:
        rows = [r for r in manifest['files'] if r['destination'].split('/')[1] == volume]
        manifest['volumes'][volume] = {'path': str(args.output / volume), 'files': len(rows),
                                       'file_bytes': sum(r['bytes'] for r in rows)}
    (args.output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'output': str(args.output), 'volumes': manifest['volumes']}))


if __name__ == '__main__':
    main()
