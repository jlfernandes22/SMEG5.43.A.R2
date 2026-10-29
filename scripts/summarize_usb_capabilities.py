#!/usr/bin/env python3
"""Index observed sandbox evidence and recheck the untouched original backups.

Visual findings are recorded separately after inspecting native framebuffers.
This script neither launches QEMU nor accesses physical devices.
"""
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT/'artifacts/phase11/usb-capabilities'
RUNS = ROOT/'artifacts/phase8/usb-maintenance/runs'


def read(path):
    return json.loads(path.read_text())


def main():
    visual = read(OUT/'visual-verification.json')
    for item in visual.values():
        assert hashlib.sha256((ROOT/item['screenshot']).read_bytes()).hexdigest() == item['screenshot_sha256']
    original = ROOT/'artifacts/live_car_backup/2026-10-27-native-usb'
    manifest = read(original/'copy-manifest.json')
    for entry in manifest['files']:
        assert hashlib.sha256((original/'usb'/entry['path']).read_bytes()).hexdigest() == entry['sha256']
    audits = {}
    for name in ['read-only/audit-control.json', 'single-key/audit-repeat.json',
                 'portal-path/audit.json', 'portal-restore/audit.json']:
        audit = read(OUT/name)
        assert not audit['original_backup_mismatches']
        assert len(audit['databases']) == 7
        assert all(d['native_checksums_valid'] and d['sqlite_integrity'] == 'ok' for d in audit['databases'])
        audits[name] = {'valid_databases': 7, 'native_module_receipt': audit['native_module_log']}
    assert visual['liveCONTENT18']['observed']['touch_count'] == 1
    assert visual['liveRESTOREcold21']['observed']['stock_connect_apps_brochure']
    cold = read(ROOT/'artifacts/phase10/int-e-patch/runs-usbwebreboot1/stock/result.json')
    assert not any(stage['sites'] for stage in cold['ram_patch_events'])
    report = {
        'scope': 'Disposable QEMU images, original German INT_E databases, AUDIO_BT_256 application',
        'physical_device_access': False,
        'physical_write_package_created': False,
        'original_backup_files_sha256_verified': len(manifest['files']),
        'portal_test': {
            'native_loader': '/bd0/FLYING/doctor_smeg_plus_i.inf: TemporaryBootRom maintenance module',
            'metadata_validation': 'Native CRC checksum; not a vendor cryptographic signature',
            'intended_parameter': {'database': 'up_config.sqlite', 'table': 'UP_Keys',
                'where': {'Section': 'internet', 'Name': 'URL_PSA_portal', 'Idx': 0},
                'column': 'StringValue', 'type': 4,
                'from': '/SYSTEM/internet_default/portal/index.html',
                'to': '/bd0/SMEG_CAP/index.html'},
            'method': 'Backup first, guarded native UP API one-key request; no application instruction writes',
            'other_feature_flags_in_this_seed': {'Web_active': 0, 'Wifi_active': 0, 'Smartapps': 0, 'PSA_portal_active': 1},
            'cold_boot_html_javascript_touch': True,
            'cold_boot_stock_portal_restoration': True,
            'preservation_limit': 'Native boot also updates bookkeeping such as HarmoniesChecked; audits list all differences. Original backups are unchanged.',
            'physical_car_write_tested': False,
        },
        'browser_compatibility': {
            'javascript_engine': 'Legacy engine; use only individually tested APIs',
            'native_read_only_objects_observed': ['GetCarTime.Hours()', 'GetCarTime.Minutes()',
                'GetCar.Speed()', 'GetCar.Autonomy()', 'GetCarTrip1.Mileage()'],
            'car_getter_data_scope': 'Emulated ECU fixture values; physical car not tested',
            'JSON_compatibility': 'Original portal bundles a JSON.parse shim. Separate raw-file retrieval from JSON parser availability.',
            'final_verified': visual.get('liveRAW24', {}).get('observed', {}),
            'failed_short_wait_capture': 'A black view after four seconds is inconclusive; later runs render with a longer settling time.',
        },
        'internet_flag_test': {
            'native_one_key_Web_active_save': True,
            'persists_after_cold_boot': True,
            'INT_E_full_web_unlocked': False,
            'cold_boot_observations': [e for e in cold['events'] if e['name'] in
                ['backend_web_input', 'backend_ram_limit', 'backend_return']],
        },
        'usb_instruction_patch_test': {
            'successful': False,
            'observed': 'Data access exception at the first application-text store, targeting 0x0227f7b4; no verified USB deployment of the debugger RAM patches.',
            'evidence': 'artifacts/phase8/usb-maintenance/runs/liveRAM13/serial.log',
        },
        'other_limits': {
            'normal_usb_flash_drive_provides_stock_apps_network_device': False,
            'official_online_apps_backend_working': 'unverified',
            'bluetooth_internet_DUN_PAN_USB_enablement': 'unverified',
            'extra_INT_E_themes': 'unverified; native A9 LIST_AUDIO_BT maps only groups 4 and 5 (SQUARE/WARMLIGHT)',
            'physical_ECO_default_off_traction_parking_controls': 'no verified USB parameter route; emulator ECU fixtures are not physical-car proof',
            'CarPlay_Android_Auto_navigation_unlock': 'unverified',
            'native_browser_bindings': 'Static Qt metadata recorded in browser-native-bindings.json; only individually observed getter calls are runtime evidence',
        },
        'audits': audits, 'visual_verification': visual,
        'runs': {case: read(RUNS/case/'result.json') for case in visual},
    }
    for case, target in [('liveCONTENT18', 'usb-browser-touch.png'),
                         ('liveRESTOREcold21', 'stock-portal-restored.png'),
                         ('liveSTAGED22', 'browser-capabilities.png'),
                         ('liveRESOURCES23', 'browser-native-readonly.png')]:
        shutil.copyfile(ROOT/visual[case]['screenshot'], OUT/target)
    if 'liveRAW24' in visual:
        shutil.copyfile(ROOT/visual['liveRAW24']['screenshot'], OUT/'browser-final-verification.png')
    (OUT/'results.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'report': str(OUT/'results.json'), 'original_backup_files_verified': len(manifest['files']),
                      'physical_device_access': False, 'verified_visual_runs': list(visual)}))


if __name__ == '__main__':
    main()
