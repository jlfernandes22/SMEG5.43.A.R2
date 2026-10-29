#!/usr/bin/env python3
"""Read original theme assets, car DB rows and guarded native eligibility sites.

Writes analysis only to a fresh Phase15 JSON file. Does not alter databases,
firmware, NAND images, native devices, or a running emulator.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import sqlite3
import struct

from inspect_internet_harmony import bank

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'artifacts/phase2/applications/AUDIO_BT_256/app.bin'
APP_SHA = '2ff81057b66d02daa9c4b9687f5407396425f81555b80d02feb6672aebb89925'
BACKUP = ROOT / 'artifacts/live_car_backup/2026-10-27-native-usb/usb/SMEG_BACKUP'
PLAN = [
    (10, 'SQUARE', 1, 1), (1, 'GRAPHIC', 1, 2), (8, 'REDLINE', 1, 3), (7, 'ESSENTIEL', 1, 4),
    (11, 'WARMLIGHT', 2, 1), (2, 'ELLIPTIC', 2, 2), (3, 'CUBIC', 2, 3), (4, 'REFLEX', 2, 4),
]
SITES = {
    0x01612afc: '409e046c',  # true Harm_i -> name lookup
    0x01612b08: '2b99000b',  # twelve zero-indexed iterations
    0x01612fac: '3884cd24',  # harmony%d literal
    0x0161309c: '40beff80',  # empty name rejected
    0x016114b0: '3af1006c',  # GetSkinList map this+6c
    0x015c5c4c: '3884aa98',  # harm%d_offset_area literal
    0x015c5ab0: '38a0000c',  # native selected Harmony file write length12
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def database_rows(name):
    path = BACKUP / name
    stored = path.read_bytes()
    raw = gzip.decompress(stored) if stored[:2] == b'\x1f\x8b' else stored
    c = sqlite3.connect(':memory:')
    c.deserialize(raw)
    c.execute('PRAGMA trusted_schema=OFF')
    assert c.execute('PRAGMA integrity_check').fetchall() == [('ok',)]
    rows = c.execute('SELECT Section,Name,Type,Idx,IntValue,StringValue FROM UP_Keys WHERE '
                     "(Section='display' AND Name LIKE 'Harm_%') OR "
                     "(Section='supervisor' AND Name LIKE 'harm%') OR "
                     "(Section='display_configuration' AND Name='Display_Color') OR "
                     "(Section='vehicle_configuration' AND Name='Audio_Harm')").fetchall()
    c.close()
    return {'source': str(path.relative_to(ROOT)), 'stored_sha256': sha(stored),
            'rows': [dict(zip(('Section', 'Name', 'Type', 'Idx', 'IntValue', 'StringValue'), row)) for row in rows]}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    out = args.output.resolve()
    assert out.is_relative_to(ROOT / 'artifacts/phase15/theme-analysis') and not out.exists()
    data = APP.read_bytes()
    assert sha(data) == APP_SHA
    for address, expected in SITES.items():
        assert data[address - 0x01000000:address - 0x01000000 + 4].hex() == expected
    assets = []
    for group in range(1, 6):
        original, _, entries = bank(group)
        for index, entry in enumerate(entries):
            record = original[0x824 + index * 216:0x824 + (index + 1) * 216]
            assets.append({'original_package_group': group, 'entry_index_zero_based': index,
                           'name': entry['theme'], 'header_entry_index': struct.unpack_from('>I', record, 196)[0],
                           'universal_ID': struct.unpack_from('>I', record, 200)[0],
                           'expanded_bytes': entry['expanded_bytes'], 'compressed_bytes': len(entry['_payload']),
                           'window_count': entry['window_count'], 'Internet_window_count': len(entry['internet_windows']),
                           'source_sha256': entry['source_sha256']})
    databases = {name: database_rows(name) for name in ('up_config.sqlite', 'up_common.sqlite')}
    indexed = {name: {(r['Section'], r['Name'], r['Idx']): r for r in item['rows']} for name, item in databases.items()}
    changes = []
    for ID, name, physical_bank, entry in PLAN:
        for db, section, key, column, value in [
            ('up_config.sqlite', 'display', 'Harm_' + str(ID), 'IntValue', 1),
            ('up_common.sqlite', 'supervisor', 'harmony' + str(ID), 'StringValue', name),
            ('up_common.sqlite', 'supervisor', 'harm' + str(ID) + '_offset_area', 'IntValue', physical_bank * 100 + entry),
        ]:
            row = indexed[db][section, key, 0]
            if row[column] != value:
                changes.append({'database': db, 'table': 'UP_Keys', 'where': {'Section': section, 'Name': key, 'Idx': 0, 'Type': row['Type']},
                                'column': column, 'old': row[column], 'proposed': value})
    result = {
        'read_only_analysis': True, 'VM_access': False, 'physical_device_access': False,
        'original_app_sha256': APP_SHA, 'guarded_instructions': {hex(k): v for k, v in SITES.items()},
        'assets': assets, 'original_theme_database_rows': databases,
        'native_eligibility': {
            'ReadSkinConfig': '016127c4: GetConfigKeys(display) and GetCommonKeys(supervisor)',
            'loop': '01612b08 compares zero-index against11; GetKeyBool(display,Harm_i) at01612b7c; true branch01612afc->01612f68',
            'name': 'Format harmony%d01612fac; GetKeyString(supervisor,name)01613000; empty names rejected01613094/0161309c',
            'map': 'Enabled nonempty names inserted into DriveConfig this+0x6c; GetSkinList0161143c iterates map without a two-item limit',
            'menu': 'C_HMI_CONFIG_SkinSettingWithTFT_M3Z_Z4::SetScreenProperties024be0ac calls GetSkinList024be29c and builds list until vector end; selection calls SetSystemSkin024be084',
            'diagnostic_write_guard': 'IsHarmonyCanBeActivatedInMenu015ed92c accepts enum1..12 with nonempty supervisor/harmonyN; does not require a binary bypass',
        },
        'native_mapping': {
            'offset_area': 'Physical native bank index*100 + one-based entry; package BigHarmony_4/5 correspond to native physical banks1/2',
            'forward': 'upgrade_256.out C_UPG_MODULE_Interface::GetBigHarmonyOffsetFromNumber .texte81ec multiply100; e81f4 add entry; e81fc store',
            'reverse': 'SaveActivated_BigHarmonyNumber .text105c4..105f8 divides by100, remainder then GetBigHarmonyNumber .text10690',
            'persist': 'C_DiagImp::SaveSkinInHarmonyIniFile015c58b0 reads supervisor/harm%d_offset_area015c5c4c/015c5c7c, writes HARMONY=<value> as12bytes015c5ab0; default101only for input0',
            'selected_HMI_ID_preserved': 10, 'selected_native_offset_preserved': 101,
            'separate_CAN_mapping': 'supervisor/harmN_number populates GetUniversalSkinNumber0160eb28 map and reverse01610840; original live values all0. Preserve these unrelated network values unless native tests show a need.',
        },
        'proposed_theme_plan': [{'HMI_ID': ID, 'name': name, 'native_physical_bank': group, 'entry_one_based': entry,
                                 'native_offset_area': group * 100 + entry} for ID, name, group, entry in PLAN],
        'proposed_database_changes_only_NOT_APPLIED': changes,
        'new_binary_eligibility_changes_required_by_inspected_paths': False,
        'limits': ['Eight unique names; original package also has duplicate GRAPHIC/ESSENTIEL variants for other vehicles.',
                   'Original assets and valid indices do not prove cross-profile loadability; each theme requires emulator cold selection/render/reboot checks.',
                   '512MiB emulator RAM does not prove physical INT_E256 memory sufficiency.',
                   'Changing a theme normally persists Display_Color and Harmony.ini; test copies must keep original car backup intact.',
                   'Vehicle motion/network availability checks remain intact; no safety/availability checks are bypassed.'],
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'analysis': str(out.relative_to(ROOT)), 'original_variants': len(assets),
                      'proposed_unique_themes': len(PLAN), 'proposed_DB_row_changes': len(changes),
                      'original_app_unchanged': sha(APP.read_bytes()) == APP_SHA}))


if __name__ == '__main__':
    main()
