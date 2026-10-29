#!/usr/bin/env python3
"""Sequential native UI switches from the USB-installed sandbox baseline.

Uses front-panel/touch events only. Saves actual screenshots, native restart
logs and stopped NAND selections. Visual review is still required.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

from run_usb_probe import QMP

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from audit_warmlight_single_flag import read_snapshot

BASE=ROOT/'artifacts/phase20/native-switch-tests'
SOURCE=ROOT/'artifacts/phase8/usb-maintenance/runs/T20ACTIVATE03/nand.raw'
CASES=[('GRAPHIC',1,102),('ELLIPTIC',2,202),('CUBIC',3,203),('ESSENTIEL',7,104),('REDLINE',8,103)]


def main():
    assert not BASE.exists() and SOURCE.is_file() and not SOURCE.is_symlink()
    BASE.mkdir(parents=True)
    source_sha=hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    results=[]
    for theme,uid,code in CASES:
        out=BASE/theme;out.mkdir()
        tag='P20SW'+theme
        runtime=ROOT/'artifacts/phase15'/('runtime-'+tag)
        prefix='/tmp/smeg-p15-'+tag
        result=dict(theme=theme,requested_HMI=uid,requested_bank_entry=code,
                    physical_devices_accessed=False,USB_attached=False,RAM_patches=False,
                    visual_review_required=True)
        q=None
        with (out/'controller.log').open('w')as log:
            proc=subprocess.Popen([sys.executable,'emulation/test_all_themes.py','--nand',str(SOURCE),
                '--tag',tag,'--seconds','300','--ram-mib','256','--native-memory',
                '--boot-info-frame','0f:94040000000000'],cwd=ROOT,stdout=log,stderr=subprocess.STDOUT)
            try:
                time.sleep(45)
                if proc.poll() is not None:raise RuntimeError('Emulator exited during initial boot')
                q=QMP(prefix+'.qmp')
                def shot(name):
                    path=out/(name+'.png')
                    q.call('screendump',{'filename':str(path),'format':'png'})
                    return path
                def tap(x,y,hold=.6):
                    q.call('input-send-event',{'events':[
                        {'type':'abs','data':{'axis':'x','value':round(x*32767/799)}},
                        {'type':'abs','data':{'axis':'y','value':round(y*32767/479)}},
                        {'type':'btn','data':{'button':'left','down':True}}]})
                    time.sleep(hold)
                    q.call('input-send-event',{'events':[{'type':'btn','data':{'button':'left','down':False}}]})
                variant=q.call('qom-get',{'path':'/machine','property':'frontpanel-key-variant'})
                key=1 if variant==0xa1 else 0
                q.call('qom-set',{'path':'/machine','property':'frontpanel-event','value':key*256+1})
                time.sleep(.8)
                q.call('qom-set',{'path':'/machine','property':'frontpanel-event','value':key*256+2})
                time.sleep(2);shot('native-main-menu')
                tap(250,215);time.sleep(3);shot('native-settings')
                tap(675,235);time.sleep(3);shot('chooser-initial')
                if theme!='REDLINE':tap(30,90,1);time.sleep(2)
                image=shot('chooser-target')
                from PIL import Image
                opened=Image.open(image);labels=[]
                for row,y in enumerate([95,153,210,270,326],1):
                    crop=out/f'ocr-row{row}.png'
                    opened.crop((65,y-25,490,y+25)).resize((850,100)).save(crop)
                    text=subprocess.run(['tesseract',str(crop),'stdout','--tessdata-dir',
                        str(ROOT/'artifacts/phase15/ocr'),'--psm','7','-c',
                        'tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ'],capture_output=True,text=True,check=True).stdout
                    labels.append(re.sub('[^A-Z]','',text))
                result['chooser_OCR_labels']=labels
                if theme not in labels:raise RuntimeError('Exact requested chooser label not visible; refusing blind selection')
                tap(225,[95,153,210,270,326][labels.index(theme)])
                time.sleep(2);shot('selected-preview')
                serial=runtime/'serial.log'
                before=serial.read_text(errors='replace')
                restarts=before.count('ffxInit : Mounting /SYSTEM_DATA disk')
                tap(58,421);time.sleep(3);shot('native-loading')
                time.sleep(45)
                ready=False
                for attempt in range(9):
                    if proc.poll() is not None:raise RuntimeError('Emulator exited after theme switch')
                    screen=shot(f'after-switch-{attempt:02d}')
                    text=subprocess.run(['tesseract',str(screen),'stdout','--tessdata-dir',
                        str(ROOT/'artifacts/phase15/ocr'),'--psm','6'],capture_output=True,text=True,check=True).stdout
                    native=serial.read_text(errors='replace')
                    if any(w in text.lower() for w in ['temas','regula','radio','rádio','memoria','memória']) and 'carregamento' not in text.lower():
                        (out/'final.png').write_bytes(screen.read_bytes())
                        result.update(final_screen_OCR=text,native_restart_seen=native.count('ffxInit : Mounting /SYSTEM_DATA disk')>restarts)
                        ready=True;break
                    time.sleep(10)
                result['application_render_candidate_ready']=ready
                if not ready:raise RuntimeError('No confirmed application text after bounded native theme restart')
                q.call('qom-set',{'path':'/machine','property':'frontpanel-event','value':key*256+1})
                time.sleep(.8)
                q.call('qom-set',{'path':'/machine','property':'frontpanel-event','value':key*256+2})
                time.sleep(3);shot('after-switch-main-menu')
                q.call('quit');q.close();q=None
                proc.wait(timeout=15)
                with tempfile.TemporaryDirectory()as td:
                    snap=read_snapshot(runtime/'nand.raw',Path(td),'switch',observe=True)
                rows=snap['databases']['up_common.sqlite']['rows']['UP_Keys']['rows']
                actual=[r['IntValue']for r in rows if (r['Section'],r['Name'],r['Idx'])==('display_configuration','Display_Color',0)]
                result.update(saved_HMI=actual,saved_Harmony_ini_hex=snap['Harmony.ini'].hex(),
                              persisted_selection_verified=actual==[uid] and snap['Harmony.ini']==f'HARMONY={code}\0'.encode(),
                              original_application_byte_exact=snap['containers'][0]['full_native_payload_exact'],
                              all_seven_databases_valid=all(d.get('sqlite_integrity_and_INF_valid')for d in snap['databases'].values()))
                native=serial.read_text(errors='replace')
                result['fatal_exception_lines']=[l for l in native.splitlines()if any(x in l.lower()for x in
                    ['data access','exception current instruction','task is suspended','unhandled exception'])]
                result['screenshots']={p.name:hashlib.sha256(p.read_bytes()).hexdigest()for p in out.glob('*.png')}
            except Exception as exc:
                result['error']=repr(exc)
            finally:
                if q:
                    try:q.call('quit')
                    except (OSError,EOFError):pass
                    q.close()
                if proc.poll() is None:
                    (runtime/'STOP').touch()
                    try:proc.wait(timeout=15)
                    except subprocess.TimeoutExpired:proc.terminate();proc.wait(timeout=10)
                result['controller_exit_code']=proc.returncode
        result['source_unchanged']=hashlib.sha256(SOURCE.read_bytes()).hexdigest()==source_sha
        (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
        results.append(result)
        (BASE/'results.json').write_text(json.dumps(results,indent=2)+'\n')
        print(json.dumps({'case':theme,'persisted_selection_verified':result.get('persisted_selection_verified'),
                          'render_candidate_ready':result.get('application_render_candidate_ready'),
                          'error':result.get('error'),'result':str(out/'result.json')}),flush=True)


if __name__=='__main__':main()
