#!/usr/bin/env python3
"""Summarize native USB network eligibility tests without physical access."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'artifacts/phase12/usb-network'
RUNS=ROOT/'artifacts/phase8/usb-maintenance/runs'


def read(p):return json.loads(p.read_text())


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--matched-ui-verdict',choices=['pending','menu-visible','menu-not-visible'],default='pending')
    p.add_argument('--resource-ui-verdict',choices=['pending','menu-visible','menu-not-visible'],default='pending')
    p.add_argument('--hotplug-ui-verdict',choices=['pending','menu-visible','menu-not-visible'],default='pending')
    a=p.parse_args()
    original=ROOT/'artifacts/live_car_backup/2026-10-27-native-usb'
    manifest=read(original/'copy-manifest.json')
    for e in manifest['files']:
        assert hashlib.sha256((original/'usb'/e['path']).read_bytes()).hexdigest()==e['sha256']
    results={}
    for case in ['netCONFIG01','netAGENDA02','netDESKTOP03','netBROWSER04','netREBOOT05','netNAVcontrol06','netMATCHED07',
                 'netMENU08','netPLAIN09','netPRESENCE10','netEARLY11','netASYNC12','netBOOT13','netBOOT14','netBOOT15','netASSET16','netHOT17']:
        folder=RUNS/case
        if not(folder/'result.json').exists():continue
        result=read(folder/'result.json')
        item={'controller_result':result,'source_run':str(folder.relative_to(ROOT))}
        for name in ['network-trace','cold-network-trace']:
            trace=folder/name/'trace.json'
            if trace.exists():
                item[name]=read(trace);assert not item[name].get('error')
                assert item[name]['debugger_memory_writes'] is False
        receipt=subprocess.run(['mtype','-i',str(folder/'usb.raw')+'@@1048576',
            '::/SMEG_BACKUP/network.txt'],capture_output=True)
        if receipt.returncode==0:item['native_usb_receipt']=receipt.stdout.decode()
        early=subprocess.run(['mtype','-i',str(folder/'usb.raw')+'@@1048576',
            '::/SMEG_EARLY_NET/report.txt'],capture_output=True)
        if early.returncode==0:item['native_early_receipt']=early.stdout.decode()
        item['controller_completed_without_error']=not result.get('error') and result.get('returncode')==0
        serial=folder/'serial.log'
        if serial.exists():
            text=serial.read_text(errors='replace')
            item['serial_status']={
                'serial_log':str(serial.relative_to(ROOT)),
                'task_exception_markers':len(re.findall(r'Exception\s+in',text,re.I)),
                'invalid_free_markers':len(re.findall(r'memPartFree:\s*invalid|Memory Free Error',text,re.I)),
                'panic_print_headers':len(re.findall(r'Date of panic',text,re.I)),
                'qemu_returncode':result.get('returncode'),
                'interpretation':'A rendered menu is not a clean full-system boot; native startup/timing and hardware warnings remain. Serial output is interleaved.'}
        receipt_text=item.get('native_early_receipt',item.get('native_usb_receipt',''))
        item['native_module_status']=('aborted' if 'ABORT ' in receipt_text else 'completed' if 'FINISHED ' in receipt_text else 'no_completion_receipt')
        if case=='netBOOT14':
            item['diagnostic_failure']='Probe called CMMSQLRequest D0 on a stack object, triggering memPartFree. Stopped intentionally. Corrected to D1 for netBOOT15.'
        results[case]=item
    cold=results['netREBOOT05']['cold-network-trace']['events']
    hot=results['netREBOOT05']['network-trace']['events']
    before=next(e for e in cold if e['name']=='desktop_internet_availability')
    after=next(e for e in hot if e['name']=='desktop_internet_availability')
    assert before['inputs']['INT_E']==1 and before['web_available']==0
    assert after['inputs']['INT_E']==0 and after['web_available']==1
    cached=next(e for e in hot if e['name']=='isFullWebAvailable')
    assert bytes.fromhex(cached['availability'])[1]==1
    audits={}
    allowed={('internet','Web_active'),('upgrade','HarmoniesChecked'),
             ('supervisor','Last_Source'),('supervisor','Last_Source_Priority'),
             ('Desktop_services','Last_application_ID')}
    for name in ['config/audit.json','agenda/audit-generated.json','desktop/audit.json','browser/audit.json','reboot-audit.json','matched-audit.json',
                 'menu/audit.json','plain-audit.json','presence/audit.json','early/audit.json','early-async/audit.json',
                 'early-bootstrap/audit.json','early-bootstrap-v2/audit.json','early-bootstrap-v3/audit.json','resource-control/audit.json','resource-control/hotplug-audit.json']:
        path=OUT/name
        if not path.exists():continue
        audit=read(path);assert not audit['original_backup_mismatches']
        assert len(audit['databases'])==7
        for db in audit['databases']:
            assert db['native_checksums_valid'] and db['sqlite_integrity']=='ok'
            for table in db['pre_to_post_usb']:
                assert not table.get('schema_changed')
                assert table['table']=='UP_Keys'
                for row in table['removed']+table['added']:assert (row['Section'],row['Name'])in allowed
        audits[name]={'original_databases_valid':7,
            'original_database_changes':[{'database':x['name'],'tables':x['pre_to_post_usb']}for x in audit['databases']if x['pre_to_post_usb']],
            'generated_database_changes':[{k:v for k,v in x.items()}for x in audit.get('generated_databases',[])if x.get('pre_to_post_usb')or x.get('after_missing')]}
    reapply=read(OUT/'reboot-audit.json')
    assert all(not x['pre_to_post_usb']for x in reapply['databases'])
    assert all(not x.get('pre_to_post_usb')for x in reapply['generated_databases'])
    report={
        'scope':'Isolated QEMU copies. Original German INT_E databases; AUDIO_BT_256/BSP256 except the independent NAV control.',
        'physical_device_access':False,'physical_car_written':False,'physical_update_package_created':False,
        'original_backup_files_sha256_verified':len(manifest['files']),
        'eligibility_checks_cleared_via_native_USB':True,
        'persistent_Internet_PAN_unlock_verified':False,
        'actual_IP_lease_or_Internet_connection_verified':False,
        'matched_INT_E_menu_visual_verdict':a.matched_ui_verdict,
        'matched_INT_E_menu_verdict_scope':'Native secondary menu with stock Audio resources; a main-menu Internet tile alone is only partial success.',
        'early_USB_main_menu_Internet_tile_visually_verified':'netBOOT15' in results,
        'NAV_SQUARE_resource_control_secondary_menu_verdict':a.resource_ui_verdict,
        'normal_boot_then_native_USB_hotplug_resource_control_verdict':a.hotplug_ui_verdict,
        'special_startup_handoff_needed_for_successful_control':False if a.hotplug_ui_verdict=='menu-visible' else None,
        'NAV_control_menu_visual_verification':'Internet browser / Transfer rate / Internet connection settings visible',
        'native_sequence':[
            'Read-only backup first; exact API fingerprints checked',
            'C_CONFIG_SYSTEM::UpdateValue(HW_FLAG_SMEG_INT_E,false) updates the RAM map',
            'Clear only Bluetooth UI cached IsSmegIntegratedEHW byte; keep agenda force_no_dun untouched',
            'C_CONFIG_SYSTEM::CreateTmpDataBase refreshes generated config_system consumed by Desktop',
            'Native one-key Web_active save when initially zero; skip setter when already one',
            'C_BCM_HMI_BROWSER_CLIENT::DBUS_GetInternetAvailability refreshes existing browser cache using native calculation'],
        'derived_config_durability':{
            'factory_manager_config_row_marked_persistent':True,
            'on_disk_generated_database_row_changes_observed_on_reapply':False,
            'cold_boot_recomputes_INT_E_as_one':True,
            'legacy_receipt_correction':'Early stage4 receipt says RAM_ONLY; it also invoked the derived config SQL refresh. Use measured audit/cold-boot results rather than that label.'},
        'saved_preferences':{
            'intended_initial_change':'up_config.sqlite/UP_Keys: internet.Web_active[0], IntValue 0 -> 1; Type2',
            'unrelated_preference_changes_detected':False,
            'normal_guest_bookkeeping':'Initial tests also update Last_application_ID, Last_Source, Last_Source_Priority and HarmoniesChecked; full audit lists them.',
            'reapply_original_database_row_changes':0,'reapply_generated_database_row_changes':0,
            'firmware_instruction_writes':False,'debugger_memory_writes':False},
        'cold_boot_Desktop':before,'after_USB_Desktop':after,'after_USB_browser_cache':cached,
        'transport_limit':'Native Phone screen says Bluetooth inactive; readiness/PPP field remains0. No real radio or remote phone was used. Eligibility is not a demonstrated PAN link.',
        'audits':audits,'cases':results,
    }
    asset_report=OUT/'resource-control/assets.json'
    if asset_report.exists():
        assets=read(asset_report)
        report['compiled_GUI_resource_finding']={
            'source':str(asset_report.relative_to(ROOT)),
            'native_secondary_menu_request':assets['native_secondary_menu_request'],
            'Audio_missing_NAV_Internet_windows':assets['Audio_missing_NAV_Internet_windows'],
            'control_limit':'Whole original NAV SQUARE compiled resource substituted only in a disposable NAND. Not a minimal overlay, native USB resource installer, or physical update package.'}
    runtime=OUT/'resource-control/runtime-state.json'
    if runtime.exists():
        report['resource_control_runtime']=read(runtime)
        assert report['resource_control_runtime']['agenda_force_no_dun_management']==1
        report['force_no_dun_conclusion']='Clearing this flag is not needed for native Internet menu visibility in the resource control. This does not establish whether a particular transport uses the Agenda DUN-event handler.'
        report['remaining_USB_only_gap']='Stock Audio resources lack23 Internet windows, including native secondary menu screen3. Full rendering required an offline borrowed-resource control; deploying resources using USB is not verified.'
        report['connection_button_observations']={'settings':'Click left the Internet menu unchanged; no usable settings form verified',
            'browser':'Click opened a black content area; no HTTP navigation or connection verified',
            'real_radio_used':False,'native_profile_ready':False,'PPP_state':0}
        report['known_control_limitations']=[
            'Native logs include startup/timing panic reports and, in the normal-boot hotplug control, an anti-theft WAITING_VIN_TIMEOUT / Jammed mode warning.',
            'These controls verify native menu rendering, not a fully operational connectivity stack or suitability for the physical vehicle.']
    if 'netBOOT15' in results:
        shutil.copyfile(RUNS/'netBOOT15/main-menu.png',OUT/'int-e-early-internet-tile.png')
        shutil.copyfile(RUNS/'netBOOT15/internet.png',OUT/'int-e-stock-resources-black.png')
    if 'netASSET16' in results:
        shutil.copyfile(RUNS/'netASSET16/internet.png',OUT/'int-e-resource-control-internet.png')
    if 'netHOT17' in results:
        shutil.copyfile(RUNS/'netHOT17/internet.png',OUT/'int-e-usb-hotplug-internet.png')
        report['successful_hotplug_control']={
            'case':'netHOT17','normal_boot_then_USB_inserted':True,
            'startup_handoff_used':False,'native_InitPresenceApplication_forced':False,
            'firmware_instruction_patches':False,
            'original_car_backup_changed':False,
            'additional_saved_database_row_changes':sum(len(x['pre_to_post_usb']) for x in read(OUT/'resource-control/hotplug-audit.json')['databases']),
            'input_setting':'Web_active already1 in a prior disposable test seed; physical original remains0.',
            'resource_prerequisite':'Offline NAV SQUARE resource control; unchanged Audio application/BSP and selected bank101.',
            'menu_verified':a.hotplug_ui_verdict=='menu-visible',
            'PAN_or_IP_connection_verified':False}
    for case,name,target in [('netNAVcontrol06','internet.png','nav-internet-menu.png'),
                             ('netBROWSER04','network-trace/internet-menu.png','int-e-early-capture.png'),
                             ('netREBOOT05','network-trace/phone.png','int-e-bluetooth-state.png')]:
        shutil.copyfile(RUNS/case/name,OUT/target)
    if 'netMATCHED07'in results:
        shutil.copyfile(RUNS/'netMATCHED07/network-trace/internet-menu.png',OUT/'int-e-matched-menu.png')
    (OUT/'results.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'report':str(OUT/'results.json'),'USB_native_eligibility':True,
        'INT_E_menu_verdict':a.matched_ui_verdict,'PAN_connection_verified':False,
        'resource_control_hotplug_menu_verdict':a.hotplug_ui_verdict,
        'reapply_saved_database_row_changes':0,'original_backup_files_verified':len(manifest['files'])}))


if __name__=='__main__':main()
