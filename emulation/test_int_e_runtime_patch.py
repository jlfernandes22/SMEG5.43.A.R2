#!/usr/bin/env python3
"""Guarded runtime firmware experiments in disposable QEMU snapshots only.

Original car DB bytes and INT_E identity are preserved. No updater, native
configuration setter, physical USB, radio passthrough or car access is used.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from PIL import Image
from run_usb_probe import QMP, RSP

ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'artifacts/phase10/int-e-patch'
APP=ROOT/'artifacts/phase2/applications/AUDIO_BT_256/app.bin'
WWW=ROOT/'artifacts/phase2/applications/AUDIO_BT_256/app_segment2.bin'
CTORS={0x182d120,0x182d3f8}
STORES={0x182d1e0,0x182d4b8}
INTERACTIVE_SECONDS=0
TELEPHONE_FIRST=False
KEEP_WINDOW=False
VISIBLE_WINDOW=False
POINTS={0x182d120:'agenda_constructor_C1',0x182d3f8:'agenda_constructor_C2',0x182d1e0:'agenda_store_C1',
        0x182d4b8:'agenda_store_C2',0x27f8cd8:'HMI_ready',
        0x227f7fc:'internet_availability',0x4c170c0:'backend_entry',
        0x4c17174:'backend_web_input',0x4c171bc:'backend_ram_limit',
        0x4c171cc:'backend_return',0x1ab8890:'QWS_mouse_event',
        0x4c8fd54:'internet_openPanel',0x4cc8f70:'secondary_HandleScreenEvent',
        0x4c86c38:'isInternetProfileReady',0x4c86cec:'isFullWebAvailable',
        0x4c8fcc4:'internet_openPopup',0x4cc9554:'secondary_constructor_C1',
        0x4cc9640:'secondary_constructor_C2'}


def filehash(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()


def prepare():
    deploy=ROOT/'artifacts/phase9/live-flag-matrix/cases/baseline/deploy'
    original=ROOT/'artifacts/live_car_backup/2026-10-27-native-usb/usb/SMEG_BACKUP'
    for f in original.glob('*.sqlite*'):
        assert f.read_bytes()==(deploy/'user_data/sqlite'/f.name).read_bytes(),f.name
    target=BASE/'live-db-seed.raw'
    if target.exists():
        data=json.loads((BASE/'seed.json').read_text())
        assert filehash(target)==data['sha256']
        return target,data['sha256']
    intermediate=BASE/'active-injection.raw'
    seed=ROOT/'artifacts/phase8/usb-maintenance/runs/ROprogress1/nand.raw'
    for src,dst,page,label in ((seed,intermediate,103168,'USER_DATA'),
                               (intermediate,target,115456,'USER_DATA_BACKUP')):
        subprocess.run([sys.executable,'emulation/inject_volume.py','--input',str(src),
                        '--output',str(dst),'--source',str(deploy),'--base-page',str(page),
                        '--report',str(BASE/('seed-'+label+'.json'))],cwd=ROOT,check=True,capture_output=True)
    intermediate.unlink()
    digest=filehash(target)
    (BASE/'seed.json').write_text(json.dumps({'sha256':digest,'databases_byte_exact':7,
        'original_stored_files':14,'database_modifications':False,
        'runtime_write_policy':'QEMU -snapshot; all guest block writes discarded'},indent=2)+'\n')
    return target,digest


def run_case(case,seed,seed_hash,plan,run_id):
    out=BASE/('runs-'+run_id)/case;out.mkdir(parents=True,exist_ok=False)
    prefix='/tmp/smeg-p10-'+run_id+'-'+case
    for suffix in ('.qmp','.gdb','.monitor'):
        if Path(prefix+suffix).exists():raise RuntimeError('Control socket already exists')
    env={k:v for k,v in os.environ.items() if not k.startswith('SMEG_')}
    env.update(SMEG_NAND=str(seed),SMEG_DISPLAY='gtk,zoom-to-fit=on' if VISIBLE_WINDOW else 'none',
        SMEG_KERNEL=str(ROOT/'artifacts/phase2/package/SMEG_PLUS_UPG/BSP/SMEG_PLUS_256/vxWorks.bin'),
        SMEG_APP_VARIANT='audio_bt',SMEG_BSP_VARIANT='256',SMEG_BENCH_HW_PROFILE='int_e',
        SMEG_FAST_MEM='1',SMEG_FAST_MODULE_MEM='1',SMEG_BENCH_KEY_VARIANT='a1',
        SMEG_SOFT_GLES='1',SMEG_GL_RENDERER='software',SMEG_CONTROL_PREFIX=prefix,
        SMEG_SERIAL='file:'+str(out/'serial.log'),SMEG_WINDOW_LOG=str(out/'window.log'),
        SMEG_PIN_THREADS='0',SMEG_USB_MEDIA='',SMEG_SD_MEDIA='',SMEG_BENCH_ECU='1',
        SMEG_BENCH_VEHICLE='1',SMEG_BENCH_KEY_PROFILE='1',LP_NUM_THREADS='2')
    report={'case':case,'physical_device_access':False,'original_database_settings_changed':False,
            'input_nand':str(seed),'source_image_changed_by_this_run':False,
            'snapshot_disk_writes_discarded':True,'hardware_identity':'INT_E',
            'plan':plan,'ram_patch_events':[],'events':[],'screenshots':{}}
    proc=subprocess.Popen(['bash','emulation/launch_ui.sh','-S','-snapshot',
        '-D',str(out/'qemu.log'),'-d','unimp','-rtc','base=localtime,clock=host',
        '-action','reboot=reset'],cwd=ROOT,env=env,stdin=subprocess.DEVNULL,start_new_session=True)
    q=r=None;installed=set();stopped=True;applied=False;hmi_ready=False;keep_open=False
    counts={};started=time.monotonic();stages=set();pending_backend={}
    def checkpoint():
        (out/'progress.json').write_text(json.dumps(report,indent=2)+'\n')
    try:
        while not Path(prefix+'.gdb').exists():
            if proc.poll() is not None:raise RuntimeError('QEMU exited before startup')
            if time.monotonic()-started>30:raise TimeoutError('Control startup')
            time.sleep(.1)
        q,r=QMP(prefix+'.qmp'),RSP(prefix+'.gdb');q.s.settimeout(60);r.s.settimeout(.05)
        r.req('qSupported');r.req('?');r.req('Qqemu.PhyMemMode:1')
        for pc in POINTS:
            assert r.req(f'Z0,{pc:x},4')=='OK';installed.add(pc)
        r.send('c');stopped=False
        def memory(addr,n):
            data=r.req(f'm{addr:x},{n:x}')
            if data.startswith('E'):raise RuntimeError('Guest memory unavailable '+hex(addr))
            return bytes.fromhex(data)
        def patch(stage='base'):
            nonlocal applied
            # Validate firmware identity around the actual decision routine and
            # the two constructor stores before accepting any patch site.
            image,load=(APP,0x1000000) if stage=='base' else (WWW,0x4c00000)
            guards=((0x227f46c,32),(0x182d1c8,24),(0x182d4a0,24)) if stage=='base' else ((0x4c170c0,32),)
            with image.open('rb') as f:
                for address,length in guards:
                    f.seek(address-load);expected=f.read(length)
                    assert memory(address,length)==expected,'Firmware guard mismatch'
            selected=[item for item in plan if (int(item['pc'],16)>=0x4c00000)==(stage=='www')]
            for item in selected:
                pc=int(item['pc'],16);old=bytes.fromhex(item['old']);new=bytes.fromhex(item['new'])
                actual=memory(pc,4)
                if actual not in (old,new):raise RuntimeError('Unexpected instruction '+hex(pc))
            for item in selected:
                pc=int(item['pc'],16)
                assert r.req(f'M{pc:x},4:'+item['new'])=='OK'
                assert memory(pc,4).hex()==item['new']
            stages.add(stage)
            if stage=='base':applied=True
            report['ram_patch_events'].append({'elapsed':round(time.monotonic()-started,2),
                'stage':stage,'sites':[item['pc'] for item in selected],'guarded':True})
        def pump(seconds):
            nonlocal stopped,hmi_ready
            deadline=time.monotonic()+seconds
            while time.monotonic()<deadline:
                if proc.poll() is not None:raise RuntimeError('Guest exited')
                try:r.recv();stopped=True
                except socket.timeout:continue
                pc=r.reg(64)
                if pc not in installed:raise RuntimeError('Unexpected debugger stop '+hex(pc))
                event={'name':POINTS[pc],'pc':hex(pc),'elapsed':round(time.monotonic()-started,2)}
                if pc==0x1ab8890:
                    raw=memory(r.reg(3),8)
                    event.update(x=int.from_bytes(raw[:4],'big',signed=True),
                                 y=int.from_bytes(raw[4:],'big',signed=True),buttons=r.reg(4))
                if pc in (0x4c8fd54,0x4cc8f70,0x4c8fcc4):
                    event['arguments']=[hex(r.reg(n)) for n in (3,4,5,6)]
                if pc in (0x4c86c38,0x4c86cec):
                    obj=r.reg(3)
                    event['availability_bytes']=memory(obj+0x51390,9).hex()
                    event['PPP_state']=int.from_bytes(memory(obj+0x50df8,4),'big')
                if pc in CTORS:
                    patch()
                    with WWW.open('rb') as f:
                        f.seek(0x170c0);expected=f.read(32)
                    if memory(0x4c170c0,32)==expected and 'www' not in stages:patch('www')
                if pc==0x4c170c0:
                    if 'www' not in stages:patch('www')
                    pending_backend[r.reg(1)]=(r.reg(4),r.reg(5))
                elif pc==0x4c17174:
                    event['stored_Web_active_read']=memory(r.reg(30),1)[0]
                elif pc==0x4c171bc:
                    event['IsRamSizeLimited_return']=r.reg(3)
                    event['web_and_BT_DUN']=r.reg(28)
                elif pc==0x4c171cc:
                    ptr=pending_backend.pop(r.reg(1)+0x20,None)
                    if ptr:event.update(web_available=memory(ptr[0],1)[0],portal_available=memory(ptr[1],1)[0])
                if pc in STORES:
                    obj=r.reg(29);event.update(object=hex(obj),r0=r.reg(0),r11=r.reg(11),before=memory(obj+0xba,1)[0])
                elif pc==0x27f8cd8:
                    hmi_ready=True;event['return']=r.reg(3)
                elif pc==0x227f7fc:
                    frame=r.reg(31)
                    event['status']=r.reg(3)
                    event['inputs']={name:memory(frame+offset,1)[0] for name,offset in {
                        'SW_OPTION_INTERNET':0x44,'PSA_portal_active':0x45,'Web_active':0x46,
                        'SETUP_FLAG_BT_ACTIVATED':0x4c,'SW_OPTION_BT_DUN':0x4d,'HW_FLAG_SMEG_INT_E':0x4e}.items()}
                    ptr=[int.from_bytes(memory(frame+x,4),'big') for x in (0x5c,0x60)]
                    event.update(web_available=memory(ptr[0],1)[0],portal_available=memory(ptr[1],1)[0])
                    event['branch_bytes']={item['pc']:memory(int(item['pc'],16),4).hex() for item in plan}
                assert r.req(f'z0,{pc:x},4')=='OK';r.req('s')
                if pc in STORES:event['after']=memory(obj+0xba,1)[0]
                report['events'].append(event);checkpoint()
                counts[pc]=counts.get(pc,0)+1
                limit=40 if pc==0x1ab8890 else (4 if pc in CTORS else 8)
                if counts[pc]<limit:assert r.req(f'Z0,{pc:x},4')=='OK'
                else:installed.remove(pc)
                r.send('c');stopped=False
        deadline=started+600
        while time.monotonic()<deadline and not (applied and hmi_ready):pump(3)
        if not (applied and hmi_ready):raise TimeoutError('Firmware guard / HMI never reached')
        pump(max(15,60-(time.monotonic()-started)))
        q.call('human-monitor-command',{'command-line':'log unimp,guest_errors'})
        def screenshot(name):
            path=out/(name+'.png');q.call('screendump',{'filename':str(path),'format':'png'})
            report['screenshots'][name]=str(path.relative_to(ROOT))
        def touch(x,y):
            # Keep servicing debugger stops while the contact is held; a host
            # sleep alone can deliver down/up together to a stopped guest.
            q.call('input-send-event',{'events':[
                {'type':'abs','data':{'axis':'x','value':round(x*32767/799)}},
                {'type':'abs','data':{'axis':'y','value':round(y*32767/479)}},
                {'type':'btn','data':{'button':'left','down':True}}]})
            # Stay below native long-press timing, with frequent RSP polling.
            pump(.18)
            q.call('input-send-event',{'events':[
                {'type':'btn','data':{'button':'left','down':False}}]})
        screenshot('boot')
        if KEEP_WINDOW:
            report.update(interactive_window=VISIBLE_WINDOW,live_snapshot=True,qemu_pid=proc.pid,
                          qmp_socket=prefix+'.qmp',gdb_socket=prefix+'.gdb',
                          ram_patch_applied=applied,patch_stages_applied=sorted(stages))
            report['guest_status']=q.call('query-status')
            keep_open=True
            return report
        # Original car FMUX maps A1/key01 to the application selector;
        # key00 opens the current application's secondary menu instead.
        q.call('qom-set',{'path':'/machine','property':'frontpanel-event','value':0x102});pump(7);screenshot('menu')
        if TELEPHONE_FIRST or case=='bluetooth_menu_only':
            touch(550,215);pump(10);screenshot('telephone')
            touch(35,230);pump(10);screenshot('telephone-secondary')
        else:
            touch(400,215);pump(10);screenshot('internet')
            touch(35,230);pump(10);screenshot('internet-secondary')
            touch(190,210);pump(10);screenshot('browser-attempt')
        action_file=out/'actions.jsonl';action_index=0
        # Optional local inspector queue for this disposable VM. No physical
        # interfaces are exposed; only native pointer/front-panel input.
        interactive_deadline=time.monotonic()+INTERACTIVE_SECONDS
        finish=False
        while time.monotonic()<interactive_deadline and not finish:
            if action_file.exists():
                actions=[json.loads(line) for line in action_file.read_text().splitlines() if line]
                for action in actions[action_index:]:
                    if action['kind']=='tap':touch(action['x'],action['y']);pump(action.get('settle',4))
                    elif action['kind']=='menu':q.call('qom-set',{'path':'/machine','property':'frontpanel-event','value':0x102});pump(4)
                    elif action['kind']=='finish':finish=True
                    else:raise ValueError('Unknown inspector action')
                    if action.get('screenshot'):
                        name=action['screenshot']
                        assert name.replace('-','').isalnum()
                        screenshot(name)
                    action_index+=1;checkpoint()
            pump(.5)
        report['guest_status']=q.call('query-status')
        report['ram_patch_applied']=applied
        report['patch_stages_applied']=sorted(stages)
        if any(int(p['pc'],16)>=0x4c00000 for p in plan) and 'www' not in stages:
            raise RuntimeError('WWW stage not loaded: backend patch could not be tested')
    except Exception as exc:
        report['error']=repr(exc)
    finally:
        try:
            if r:
                if not stopped:r.s.sendall(b'\x03');r.recv();stopped=True
                for pc in installed:r.req(f'z0,{pc:x},4')
                r.req('D');r.s.close()
            if q:
                q.call('cont' if keep_open else 'quit');q.close()
        except (OSError,EOFError,RuntimeError):pass
        if not keep_open:
            try:proc.wait(timeout=8)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()
        report['exit_code']=proc.returncode
        serial=(out/'serial.log').read_text(errors='replace') if (out/'serial.log').exists() else ''
        report['serial_exception_lines']=[l for l in serial.splitlines() if any(t in l.lower()
            for t in ('data access exception','task is suspended','unhandled exception'))]
        report['seed_database_image_unchanged']=filehash(seed)==seed_hash
        (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({'case':case,'error':report.get('error'),'screenshots':len(report['screenshots']),
            'events':len(report['events']),'image_unchanged':report['seed_database_image_unchanged']}),flush=True)
    return report


def main():
    global INTERACTIVE_SECONDS,TELEPHONE_FIRST,KEEP_WINDOW,VISIBLE_WINDOW
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run-id',default='first');p.add_argument('--workers',type=int,default=5,choices=range(1,7))
    p.add_argument('--cases',nargs='+')
    p.add_argument('--seed',type=Path,help='Explicit stopped emulator NAND artifact; used with -snapshot and never modified')
    p.add_argument('--interactive-seconds',type=int,default=0,choices=range(0,601))
    p.add_argument('--telephone-first',action='store_true')
    p.add_argument('--window',action='store_true',help='Leave a native GTK window open after guarded patches; no scripted clicks')
    p.add_argument('--keep-running',action='store_true',help='Leave a headless snapshot available for a separate tracer after guarded RAM patches')
    a=p.parse_args()
    INTERACTIVE_SECONDS=a.interactive_seconds
    TELEPHONE_FIRST=a.telephone_first
    KEEP_WINDOW=a.window or a.keep_running
    VISIBLE_WINDOW=a.window
    if KEEP_WINDOW and (a.workers!=1 or not a.cases or len(a.cases)!=1):
        p.error('--window requires --workers 1 and exactly one case')
    if not a.run_id.isalnum():p.error('Alphanumeric run ID required')
    analysis=json.loads((BASE/'analysis.json').read_text());plans=analysis['cases']
    cases=a.cases or list(plans)
    if any(c not in plans for c in cases):p.error('Unknown case')
    if a.seed:
        seed=a.seed.resolve()
        if not seed.is_relative_to(ROOT/'artifacts') or not seed.is_file():
            p.error('--seed must be a regular workspace artifact')
        seed_hash=filehash(seed)
    else:seed,seed_hash=prepare()
    results={}
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.workers) as pool:
        jobs={pool.submit(run_case,c,seed,seed_hash,plans[c],a.run_id):c for c in cases}
        for job in concurrent.futures.as_completed(jobs):
            case=jobs[job]
            try:results[case]=job.result()
            except Exception as exc:results[case]={'case':case,'error':repr(exc)}
            (BASE/('results-'+a.run_id+'.json')).write_text(json.dumps(results,indent=2)+'\n')
    if any(r.get('error') for r in results.values()):sys.exit(1)
    if KEEP_WINDOW:
        # Keep the user service alive while its GUI child is in use. The
        # ready result is already saved; closing QEMU ends this controller.
        for result in results.values():
            os.waitpid(result['qemu_pid'],0)


if __name__=='__main__':main()
