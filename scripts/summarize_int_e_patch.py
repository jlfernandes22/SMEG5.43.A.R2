#!/usr/bin/env python3
"""Audit original files and collect RAM-only INT_E emulator evidence."""
import gzip
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'artifacts/phase10/int-e-patch'
BACKUP=ROOT/'artifacts/live_car_backup/2026-10-27-native-usb'


def sha(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()


def main():
    manifest=json.loads((BACKUP/'copy-manifest.json').read_text())
    originals=[]
    for entry in manifest['files']:
        path=BACKUP/'usb'/entry['path']
        originals.append({'path':entry['path'],'sha256':sha(path),
                          'unchanged':sha(path)==entry['sha256']})
    decoded=[]
    for path in sorted((BACKUP/'usb/SMEG_BACKUP').glob('*.sqlite')):
        decoded.append({'database':path.name,'decoded_matches_original':
                        gzip.decompress(path.read_bytes())==(BACKUP/'decoded'/path.name).read_bytes()})
    analysis=json.loads((BASE/'analysis.json').read_text())
    firmware={}
    for variant,profile in analysis['profiles'].items():
        firmware[variant]=sha(ROOT/profile['image'])==profile['sha256']
    firmware['AUDIO_BT_256_segment2']=sha(ROOT/analysis['backend']['image'])==analysis['backend']['image_sha256']
    seed=json.loads((BASE/'seed.json').read_text())
    runs=[]
    for path in sorted(BASE.glob('runs-*/*/result.json')):
        data=json.loads(path.read_text());events=data.get('events',[])
        runs.append({'run':path.parent.parent.name,'case':data['case'],
            'result':str(path.relative_to(ROOT)), 'error':data.get('error'),
            'qemu_exit_code':data.get('exit_code'),
            'logged_fatal_exceptions':data.get('serial_exception_lines',[]),
            'seed_image_unchanged':data.get('seed_database_image_unchanged'),
            'desktop_web_available':sorted({e['web_available'] for e in events
                if e['name']=='internet_availability'}),
            'backend_web_available':sorted({e['web_available'] for e in events
                if e['name']=='backend_return' and 'web_available' in e}),
            'agenda_force_no_dun_after_store':sorted({e['after'] for e in events
                if e['name'].startswith('agenda_store')}),
            'screenshots':data.get('screenshots',{})})
    report={'physical_device_access':False,'database_modifications':False,
        'firmware_file_modifications':False,'patch_scope':'QEMU RAM only; -snapshot discards all guest block writes',
        'backup_files':originals,'decoded_databases':decoded,
        'firmware_files_unchanged':firmware,
        'seed_image_unchanged':sha(BASE/'live-db-seed.raw')==seed['sha256'],
        'cases_completed':sorted({r['case'] for r in runs}),
        'cases_planned':list(analysis['cases']), 'runs':runs,
        'UI_interpretation':{
            'stock_connect_apps':'Brochure. Internet tile in desktop is already present due to PSA_portal_active.',
            'desktop_INT_E_removal_alone':'Web remains unavailable with original Web_active=0.',
            'phonebook_flag_zero_alone':'No browser unlock; this field belongs to the agenda DUN handler.',
            'backend_INT_E_and_local_Web_bypass':'Native backend Web availability becomes1 and a blue side control appears. Stored Web_active remains0.',
            'native_secondary_menu_request':'Observed openPanel(0x1f40,8,0) from correctly delivered pointer events, but the captured body remains brochure.',
            'browser_ui_verified':False,'network_connection_verified':False,
            'physical_car_update_package_created':False}}
    assert all(e['unchanged'] for e in originals)
    assert all(e['decoded_matches_original'] for e in decoded)
    assert all(firmware.values()) and report['seed_image_unchanged']
    (BASE/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'completed_runs':len(runs),'completed_cases':len(report['cases_completed']),
        'all_original_files_unchanged':True,'report':str(BASE/'verification.json')}))


if __name__=='__main__':main()
