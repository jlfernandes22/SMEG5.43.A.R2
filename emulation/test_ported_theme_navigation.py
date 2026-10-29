#!/usr/bin/env python3
"""Cold navigation controls inheriting resources installed by native USB.

The only offline fixture changes are current theme selection and Harmony.ini;
the same selections were independently exercised through the native UI first.
No resource injection, memory patches, physical devices, or car packages.
"""
import hashlib
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from run_usb_probe import QMP
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from audit_warmlight_single_flag import read_snapshot
from build_all_themes_candidate import change_database

BASE=ROOT/'artifacts/phase20/ported-navigation-tests'
SOURCE=ROOT/'artifacts/phase8/usb-maintenance/runs/T20PORTED02/nand.raw'
CASES=[('GRAPHIC',1,102),('ELLIPTIC',2,202),('CUBIC',3,203),('REFLEX',4,204),
       ('ESSENTIEL',7,104),('REDLINE',8,103)]


def main():
    global BASE,SOURCE,CASES
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=SOURCE)
    parser.add_argument('--output',type=Path,default=BASE)
    parser.add_argument('--audit',type=Path,default=ROOT/'artifacts/phase20/ported-full-erase-installation-audit.json')
    parser.add_argument('--themes',nargs='+',choices=[r[0]for r in CASES]+['SQUARE','WARMLIGHT'])
    parser.add_argument('--tag-prefix',default='P20NAV')
    parser.add_argument('--offline-resource-control',action='store_true',help='Visual fixture only; explicitly NOT native USB installation evidence')
    parser.add_argument('--same-mcu-fixture',action='store_true',help='Match the explicit MCU state used by the native USB probes; not measured vehicle data')
    a=parser.parse_args();BASE=a.output.resolve();SOURCE=a.source.resolve()
    assert BASE.is_relative_to(ROOT/'artifacts/phase20') and SOURCE.is_relative_to(ROOT/'artifacts')
    assert a.tag_prefix.startswith('P20') and a.tag_prefix.isalnum()
    choices=CASES+[('SQUARE',10,101),('WARMLIGHT',11,201)]
    if a.themes:CASES=[r for r in choices if r[0]in a.themes]
    assert not BASE.exists() and SOURCE.is_file()
    if a.offline_resource_control:
        fixture=json.loads((SOURCE.parent/'fixture.json').read_text())
        assert fixture['native_USB_installation_proof']is False and fixture['emulator_only']is True
        assert fixture['sha256']==hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    else:
        result=json.loads((SOURCE.parent/'result.json').read_text())
        assert result['wait_marker_seen'] and result['returncode']==0
        audit=json.loads(a.audit.read_text())
        assert Path(audit['after'])==SOURCE
        assert audit['native_install_success'] and audit['original_application_byte_exact']
        assert all(r['preheader_byte_exact'] and r['directory_byte_exact'] and
                   all(e['source_payload_byte_exact'] and e['stored_CRC32_valid']for e in r['entries'])for r in audit['resources'])
    BASE.mkdir(parents=True)
    source_sha=hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory()as td:
        temp=Path(td);baseline=read_snapshot(SOURCE,temp,'base',observe=True)
        common=BASE/'baseline-up_common.sqlite'
        common.write_bytes((temp/'base-up_common.sqlite').read_bytes())
        Path(str(common)+'.inf').write_bytes((temp/'base-up_common.sqlite.inf').read_bytes())
    results=[]
    for theme,uid,code in CASES:
        out=BASE/theme;out.mkdir()
        user=out/'USER_DATA/user_data/sqlite';user.mkdir(parents=True)
        changed=change_database(common,user/'up_common.sqlite',
            [('display_configuration','Display_Color','IntValue',uid)])
        assert (uid==11 and not changed) or (len(changed)==1 and changed[0]['old']==11 and changed[0]['new']==uid)
        system=out/'SYSTEM_DATA';system.mkdir();(system/'Harmony.ini').write_bytes(f'HARMONY={code}\0'.encode())
        def run(*cmd):return subprocess.run(cmd,cwd=ROOT,check=True,capture_output=True)
        user_nand=out/'selection-user.raw';nand=out/'selection.raw'
        run(sys.executable,'emulation/inject_volume.py','--input',str(SOURCE),'--output',str(user_nand),
            '--source',str(out/'USER_DATA'),'--base-page','103168')
        run(sys.executable,'emulation/inject_volume.py','--input',str(user_nand),'--output',str(nand),
            '--source',str(system),'--base-page','57856')
        tag=a.tag_prefix+theme;runtime=ROOT/'artifacts/phase15'/('runtime-'+tag)
        prefix='/tmp/smeg-p15-'+tag
        record=dict(theme=theme,requested_HMI=uid,requested_native_code=code,
                    native_USB_resource_source=None if a.offline_resource_control else str(SOURCE),
                    offline_resource_control=a.offline_resource_control,resource_source=str(SOURCE),offline_selection_fixture_changes=changed,
                    original_selection_already_verified_through_native_UI=True,
                    physical_devices_accessed=False,RAM_patches=False,visual_review_required=True)
        q=None
        with (out/'controller.log').open('w')as log:
            command=[sys.executable,'emulation/test_all_themes.py','--nand',str(nand),'--tag',tag,
                '--seconds','240','--ram-mib','256','--native-memory','--boot-info-frame','0f:94040000000000']
            if a.same_mcu_fixture:command+=['--mcu-sw-release','05.e3.01','--mcu-upg-config','01ffffffffffffffffffffffffffffff','--mcu-system-config','00ff01ffffffffffffffffffff003efa']
            record['explicit_MCU_fixture_not_measured_car_data']=a.same_mcu_fixture
            proc=subprocess.Popen(command,
                cwd=ROOT,stdout=log,stderr=subprocess.STDOUT)
            try:
                time.sleep(55)
                q=QMP(prefix+'.qmp')
                def shot(name):
                    path=out/(name+'.png');q.call('screendump',{'filename':str(path),'format':'png'});return path
                def tap(x,y):
                    q.call('input-send-event',{'events':[
                        {'type':'abs','data':{'axis':'x','value':round(x*32767/799)}},
                        {'type':'abs','data':{'axis':'y','value':round(y*32767/479)}},
                        {'type':'btn','data':{'button':'left','down':True}}]})
                    time.sleep(.7);q.call('input-send-event',{'events':[{'type':'btn','data':{'button':'left','down':False}}]})
                    time.sleep(3)
                def menu():
                    variant=q.call('qom-get',{'path':'/machine','property':'frontpanel-key-variant'});key=1 if variant==0xa1 else 0
                    q.call('qom-set',{'path':'/machine','property':'frontpanel-event','value':key*256+1})
                    time.sleep(.8);q.call('qom-set',{'path':'/machine','property':'frontpanel-event','value':key*256+2})
                    time.sleep(3)
                shot('initial-application');menu();menu_image=shot('native-MENU')
                text=subprocess.run(['tesseract',str(menu_image),'stdout','--tessdata-dir',str(ROOT/'artifacts/phase15/ocr'),
                    '--psm','6'],capture_output=True,text=True,check=True).stdout
                record['MENU_OCR']=text
                record['DOTE_configuration_error']='dote' in text.lower() or 'imposs' in text.lower()
                media_touch=(236,145) if theme=='REDLINE' else (100,215)
                record['media_touch']=list(media_touch)
                tap(*media_touch);shot('native-radio')
                if theme=='ESSENTIEL':
                    menu();tap(250,215);shot('ESSENTIEL-settings')
                    tap(675,235);shot('ESSENTIEL-theme-chooser')
                q.call('quit');q.close();q=None;proc.wait(timeout=15)
                with tempfile.TemporaryDirectory()as td:snap=read_snapshot(runtime/'nand.raw',Path(td),'after',observe=True)
                rows=snap['databases']['up_common.sqlite']['rows']['UP_Keys']['rows']
                actual=[r['IntValue']for r in rows if (r['Section'],r['Name'],r['Idx'])==('display_configuration','Display_Color',0)]
                native=(runtime/'serial.log').read_text(errors='replace')
                record.update(saved_HMI=actual,selection_preserved=actual==[uid] and snap['Harmony.ini']==f'HARMONY={code}\0'.encode(),
                    original_application_byte_exact=snap['containers'][0]['full_native_payload_exact'],
                    all_seven_databases_valid=all(d.get('sqlite_integrity_and_INF_valid')for d in snap['databases'].values()),
                    fatal_exception_lines=[l for l in native.splitlines()if any(s in l.lower()for s in
                        ['data access','exception current instruction','unhandled exception','task is suspended'])])
            except Exception as exc:record['error']=repr(exc)
            finally:
                if q:
                    try:q.call('quit')
                    except (OSError,EOFError):pass
                    q.close()
                if proc.poll() is None:
                    (runtime/'STOP').touch()
                    try:proc.wait(timeout=15)
                    except subprocess.TimeoutExpired:proc.terminate();proc.wait(timeout=10)
        record['source_unchanged']=hashlib.sha256(SOURCE.read_bytes()).hexdigest()==source_sha
        record['screenshots']={p.name:hashlib.sha256(p.read_bytes()).hexdigest()for p in out.glob('*.png')}
        (out/'result.json').write_text(json.dumps(record,indent=2)+'\n');results.append(record)
        (BASE/'results.json').write_text(json.dumps(results,indent=2)+'\n')
        print(json.dumps({'theme':theme,'MENU_DOTE_error':record.get('DOTE_configuration_error'),
            'selection_preserved':record.get('selection_preserved'),'error':record.get('error')}),flush=True)


if __name__=='__main__':main()
