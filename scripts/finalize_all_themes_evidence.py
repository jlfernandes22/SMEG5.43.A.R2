#!/usr/bin/env python3
"""Assemble the final v7 USB gate from independently completed emulator proofs.

Reads artifacts only, refuses incomplete or mismatched evidence, and never
opens a physical device. Physical compatibility/recovery remain unverified.
"""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PHASE = ROOT/'artifacts/phase15'
IMAGE = PHASE/'candidate-allthemes-v7/usb.raw'
MANIFEST = PHASE/'theme-assets/all-eight-menu-colour-style-v7/manifest.json'
THEMES = {'GRAPHIC':(1,102),'ELLIPTIC':(2,202),'CUBIC':(3,203),'REFLEX':(4,204),
          'ESSENTIEL':(7,104),'REDLINE':(8,103),'SQUARE':(10,101),'WARMLIGHT':(11,201)}
SOURCES = {
    'UI':PHASE/'v7-ui-verification.json',
    'UI_runtime':PHASE/'runtime-UIV7BETA/result.json',
    'UI_asset_seed':PHASE/'ui-v7-ess.raw.harmony.json',
    'native_install':PHASE/'native256-v7/runtime-verification.json',
    'stored_state':PHASE/'native256-v7/stopped-native-audit.json',
    'cold_boot':PHASE/'native256-v7/cold-boot-verification.json',
    'largest_theme_256':PHASE/'runtime-REFV7256/verification.json',
    'normal_stock_acceptance':PHASE/'stock-cold-v7-acceptance/verification.json',
    'stock_restore':PHASE/'stock-restore256/verification.json',
    'USB_guard_review':PHASE/'theme-analysis/physical-usb-guard-final-review.json',
    'package_audit':PHASE/'candidate-allthemes-v7/candidate-independent-audit.json',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f,'sha256').hexdigest()


def check_references(value):
    if isinstance(value,dict):
        expected=value.get('sha256') or value.get('SHA256')
        if 'path' in value and expected:
            original=Path(value['path'])
            p=original if original.is_absolute() else ROOT/original
            require(not p.is_symlink() and p.resolve().is_relative_to(ROOT/'artifacts'), 'Unsafe evidence reference')
            require(p.is_file() and sha(p)==expected, 'Evidence file hash mismatch: '+str(p))
        for child in value.values():check_references(child)
    elif isinstance(value,list):
        for child in value:check_references(child)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,default=PHASE/'final-verification.json')
    a=p.parse_args();out=a.output.resolve()
    require(out.is_relative_to(PHASE) and not out.exists() and not a.output.is_symlink(), 'New Phase15 receipt required')
    data={}
    for name,path in SOURCES.items():
        require(path.is_file() and not path.is_symlink(), 'Missing completed evidence: '+str(path))
        data[name]=json.loads(path.read_text())
        check_references(data[name])
    image_sha=sha(IMAGE);manifest_sha=sha(MANIFEST)
    ui,runtime=data['UI'],data['UI_runtime']
    require(ui['status'] in ('complete','completed','passed'), 'Theme cycle is not complete')
    require(ui['candidate_USB_sha256_parent_supplied']==image_sha and ui['asset_manifest_sha256']==manifest_sha,
            'Theme screenshots do not bind the final USB and asset manifest')
    require(runtime['exit_code']==0 and runtime['source_unchanged'] is True and runtime['serial_exception_lines']==[],
            'Theme controller was not stopped cleanly with intact source')
    require(runtime['USB_attached'] is False and runtime['guest_RAM_patches'] is False,
            'UI control used unapproved guest modifications')
    require(sha(Path(runtime['source']))==runtime['source_sha256'],'UI source changed after its guard')
    seed=data['UI_asset_seed']
    require(seed['output_sha256']==runtime['source_sha256'] and seed['profile']=='audio256'
            and seed['mapping']==[4,5] and len(seed['regions'])==2,'UI seed provenance mismatch')
    for region in seed['regions']:
        expected=PHASE/'candidate-allthemes-v7/SMEG_PLUS_UPG/HARMONY'/('BigHarmony_'+str(region['group']))/'BIG_HARMONY.bin'
        require(region['group'] in (4,5) and region['source_sha256']==sha(expected)
                and region['sidecar_sha256']==sha(Path(str(expected)+'.inf')),
                'Actual UI seed does not contain the final candidate assets')
    require(set(ui['themes'])==set(THEMES),'Incomplete theme names')
    for name,(slot,code) in THEMES.items():
        t=ui['themes'][name]
        for field in ('render_visually_verified','menu_visually_verified','Internet_primary_visually_verified',
                      'Internet_secondary_visually_verified','RadioMedia_visually_verified',
                      'Colour_button_visually_verified','Colour_switch_worked','native_selection_persisted','no_hard_exceptions'):
            require(t.get(field) is True,name+' lacks '+field)
        require(t['serial_exception_lines']==[] and t['serial_preloader_code']==code
                and t['persisted_Display_Color']==slot
                and t['persisted_Harmony_ini_hex']==('HARMONY='+str(code)+'\0').encode().hex(),
                'Incorrect actual native selection for '+name)
        for key in ('render_screen','menu_screen','Internet_primary_screen','Internet_secondary_screen',
                    'RadioMedia_screen','Colour_chooser_screen','native_exit_input_log'):
            require(t.get(key,{}).get('sha256'),'Missing hashed screen/input evidence: '+name+'/'+key)
    native,cold,audit=data['native_install'],data['cold_boot'],data['stored_state']
    require(native['USB_SHA256']==image_sha and cold['final_USB_SHA256']==image_sha,'Native install image mismatch')
    require(native['RAM_MiB']==cold['RAM_MiB']==256
            and native['NAND_geometry_bytes']==cold['NAND_physical_bytes']==276824064,
            'Native install/cold boot did not use the claimed coherent256MiB model')
    for key in ('native_installation_completed','stored_candidate_bytes_and_databases_verified','raw3_regions_verified',
                'DB7_contents_verified','VM_stopped','independent_cold_boot_UI_verified','independent_cold_boot_source_unchanged'):
        require(native.get(key) is True,'Native proof lacks '+key)
    require(native['QEMU_clean_returncode']==0 and native['CPU_exception_marker_seen'] is False
            and native['guest_RAM_or_instruction_success_patches'] is False,'Native installation has unresolved failures')
    require(audit['stored_candidate_bytes_and_databases_verified'] is True
            and audit['all_seven_database_contents_verified'] is True
            and audit['all_three_raw_container_defined_regions_verified'] is True,'Stored payload audit failed')
    package_dir=PHASE/'candidate-allthemes-v7/SMEG_PLUS_UPG'
    require((ROOT/audit['package']).resolve()==package_dir,'Stored audit references another package')
    expected_offsets={'AUDIO_BT_256/AppBin/f_BigQuick.bin':0x1100000,
                      'HARMONY/BigHarmony_4/BIG_HARMONY.bin':0x2dc0000,
                      'HARMONY/BigHarmony_5/BIG_HARMONY.bin':0x4f60000}
    require({r['path'] for r in audit['raw_containers']}==set(expected_offsets),'Incorrect raw payload coverage')
    for record in audit['raw_containers']:
        require(record['source_sha256']==sha(package_dir/record['path']), 'Stored audit source differs from finalv7')
        require(any(int(m['logical_offset'],0)==expected_offsets[record['path']]
                    and (m.get('exact_payload_match') is True or m.get('native_defined_regions_match') is True)
                    for m in record['matches']), 'Payload not verified at its correct native slot')
    require(len(audit['databases'])==7,'Incorrect native database coverage')
    for database in audit['databases']:
        require(database['expected_database_contents_match'] is True and database['native_INF_valid'] is True
                and database['sqlite_integrity']=='ok','Invalid stored database: '+database['name'])
        if database['name'] in ('up_common.sqlite','up_config.sqlite'):
            require((ROOT/Path(database['expected_source'])).resolve()==
                    package_dir/'NAV/USER_DATA/user_data/sqlite'/database['name'],
                    'Modified database audit references another candidate')
    require(native['stopped_NAND_SHA256']==audit['nand_sha256']==cold['source_NAND_SHA256']
            and sha(ROOT/audit['nand'])==audit['nand_sha256'],'Installed NAND provenance mismatch')
    require(cold['cold_boot_UI_verified'] is True and cold['source_unchanged'] is True
            and cold['USB_attached'] is False and cold['guest_RAM_or_instruction_patches'] is False
            and cold['CPU_exception_or_OOM_markers_seen'] is False and cold['clean_QEMU_returncode']==0
            and cold['VM_stopped'] is True,'Independent USB-free cold boot failed')
    memory=data['largest_theme_256']
    require(memory['candidate_USB_sha256']==image_sha and memory['RAM_MiB']==256
            and memory['no_CPU_exception_or_OOM_markers'] is True and memory['source_unchanged'] is True,
            'Largest-theme memory control failed')
    stock=data['normal_stock_acceptance']
    require(stock['final_v7_USB_SHA256_before']==image_sha==stock['final_v7_USB_SHA256_after']
            and stock['native_same_version_update_confirmation_visually_verified'] is True
            and stock['installation_started'] is False and stock['source_stopped_original_stock_NAND_unchanged'] is True
            and stock['post_cancel_all_three_raw_stock_containers_byte_exact'] is True
            and stock['post_cancel_all_seven_original_car_database_contents_and_INFs_verified'] is True,
            'Unmodified stock native confirmation/cancellation proof failed')
    restore=data['stock_restore']
    require(restore['all_three_original_raw_containers_byte_exact'] is True
            and restore['all_seven_original_database_contents_verified'] is True
            and restore['native_update_reboot_and_original_SQUARE_FM_observed'] is True,'Emulated stock restore failed')
    guard=data['USB_guard_review']
    for relative,record in guard['files'].items():require(sha(ROOT/relative)==record['sha256'],'USB guard changed since review')
    require(guard['test_execution']['exit_code']==0 and guard['test_execution']['actual_completed_tests']>=21,
            'Guard regression suite failed')
    package=data['package_audit']
    require(package['virtual_USB_sha256']==image_sha and package['exact_SQL_change_count']==20
            and package['all_other_SQL_rows_columns_and_schema_preserved'] is True,'Package preservation audit failed')
    proof={'scope':'Final v7 emulator verification permits preparing the specifically identified USB; no physical-unit compatibility or recovery guarantee',
        'candidate_USB_sha256':image_sha,'asset_manifest_sha256':manifest_sha,
        'exact_native_USB_install_and_cold_boot_verified':True,
        'all_eight_theme_switches_visually_verified':True,'all_eight_themes_Internet_menu_verified':True,
        'verified_theme_names':sorted(THEMES),'unresolved_compatibility_issues':[],'fatal_guest_exceptions':[],
        'native_stock_update_confirmation_verified':True,'emulated_stock_restore_verified':True,
        'original_other_database_rows_columns_and_schema_preserved':True,'exact_SQL_change_count':20,
        'default_theme_preserved':'SQUARE/Display_Color10/HARMONY101',
        'all8_theme_UI_test_RAM_MiB':runtime['ram_mib'],'native_install_cold_boot_and_largest_theme_RAM_MiB':256,
        'physical_car_accessed':False,'physical_car_compatibility_verified':False,'physical_car_recovery_verified':False,
        'actual_Internet_HTTP_or_phone_PAN_DUN_connection_verified':False,
        'evidence':[{'path':str(path.relative_to(ROOT)),'sha256':sha(path)}for path in SOURCES.values()]}
    out.write_text(json.dumps(proof,indent=2)+'\n')
    print(json.dumps({'receipt':str(out),'candidate_USB_sha256':image_sha,'verified_themes':len(THEMES)}))


if __name__=='__main__':main()
