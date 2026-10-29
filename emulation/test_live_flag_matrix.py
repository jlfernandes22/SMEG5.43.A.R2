#!/usr/bin/env python3
"""Cold-boot live-car DB copies on AUDIO_BT_256 / INT_E; no physical devices.

The seven captured DBs are exact inputs, not a complete hardware/flash replica.
Original native menu decisions are observed with debugger breakpoints. No
availability return value, hardware identity or application branch is forced.
"""
import argparse
import concurrent.futures
import gzip
import hashlib
import json
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import time
import threading
from pathlib import Path
from PIL import Image

from run_usb_probe import QMP, RSP
from test_car_connectivity import panel, tap

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT/'artifacts/phase9/live-flag-matrix'
SEED = ROOT/'artifacts/phase8/usb-maintenance/runs/ROprogress1/nand.raw'
POINTS = {0x227f7fc: 'desktop_internet_availability',
          0x27f8cd8: 'bluetooth_smartapps_supported'}
STOP = threading.Event()


def verify_stored_flags(folder):
    db = sqlite3.connect(':memory:')
    db.deserialize(gzip.decompress((folder/'up_config.sqlite').read_bytes()))
    flags = dict(db.execute("SELECT Name,IntValue FROM UP_Keys WHERE Section='internet' "
                            "AND Name IN ('Web_active','Wifi_active','Smartapps') AND Idx=0"))
    db.close()
    return flags


def run_case(case, boot_seconds, run_id, menu_only, full_power, render_threads, native_navigation):
    if STOP.is_set():
        return {'case':case,'error':'Cancelled before launch'}
    out = BASE/('runs-'+run_id)/case
    out.mkdir(parents=True, exist_ok=False)
    deploy = BASE/'cases'/case/'deploy'
    report = {'case':case, 'profile':'AUDIO_BT_256 / SMEG_PLUS_256 / INT_E',
              'physical_device_access':False, 'native_availability_forced':False,
              'flags_before_boot':verify_stored_flags(deploy/'user_data/sqlite'),
              'trace':[], 'screenshots':{},
              'limitations':'Exact seven captured DBs; uncaptured files and peripherals remain emulator fixtures.'}
    # Populate both the active and recovery copy to avoid an older fixture
    # restoring configuration during boot. VBF headers remain native.
    intermediate = out/'active.raw'
    for input_path, output_path, base_page, label in (
            (SEED, intermediate, 103168, 'USER_DATA'),
            (intermediate, out/'nand-ui.raw', 115456, 'USER_DATA_BACKUP')):
        proc = subprocess.run([sys.executable, 'emulation/inject_volume.py',
                               '--input',str(input_path),'--output',str(output_path),
                               '--source',str(deploy),'--base-page',str(base_page),
                               '--report',str(out/('inject-'+label+'.json'))],
                              cwd=ROOT, capture_output=True, text=True)
        if proc.returncode:
            raise RuntimeError(proc.stderr or proc.stdout)
    intermediate.unlink()
    prefix = '/tmp/smeg-p9-'+run_id+'-'+case
    for suffix in ('.qmp','.gdb','.monitor'):
        if Path(prefix+suffix).exists():
            raise RuntimeError('Existing control socket: '+prefix+suffix)
    env = {k:v for k,v in os.environ.items() if not k.startswith('SMEG_')}
    env.update(SMEG_NAND=str(out/'nand-ui.raw'), SMEG_DISPLAY='none',
               SMEG_KERNEL=str(ROOT/'artifacts/phase2/package/SMEG_PLUS_UPG/BSP/SMEG_PLUS_256/vxWorks.bin'),
               SMEG_APP_VARIANT='audio_bt', SMEG_BSP_VARIANT='256',
               SMEG_BENCH_HW_PROFILE='int_e', SMEG_FAST_MEM='1', SMEG_FAST_MODULE_MEM='1',
               SMEG_BENCH_KEY_VARIANT='a1',
               SMEG_SOFT_GLES='1', SMEG_GL_RENDERER='software',
               SMEG_CONTROL_PREFIX=prefix, SMEG_SERIAL='file:'+str(out/'serial.log'),
               SMEG_WINDOW_LOG=str(out/'window.log'), SMEG_PIN_THREADS='0',
               SMEG_USB_MEDIA='', SMEG_SD_MEDIA='',
               SMEG_BENCH_ECU='1', SMEG_BENCH_VEHICLE='1', SMEG_BENCH_KEY_PROFILE='1',
               LP_NUM_THREADS=str(render_threads), MESA_GLTHREAD='false')
    io_priority = ['ionice','-c','2','-n','0'] if full_power else ['ionice','-c','3']
    proc = subprocess.Popen(io_priority+[
                             'bash','emulation/launch_ui.sh','-S','-D',str(out/'qemu.log'),'-d','unimp',
                             '-rtc','base=localtime,clock=host','-action','reboot=reset'],
                            cwd=ROOT,env=env,stdin=subprocess.DEVNULL,start_new_session=True)
    os.setpriority(os.PRIO_PROCESS, proc.pid, 0 if full_power else 19)
    q = r = None
    stopped = True
    installed = set()
    started = time.monotonic()
    try:
        while not Path(prefix+'.gdb').exists():
            if proc.poll() is not None:raise RuntimeError('QEMU exited before control startup')
            if time.monotonic()-started>20:raise TimeoutError('Control startup')
            time.sleep(.1)
        q, r = QMP(prefix+'.qmp'), RSP(prefix+'.gdb')
        # A throttled CPU can hold the QEMU I/O thread during early cache
        # maintenance. Control replies need more than the generic 5s timeout.
        q.s.settimeout(60)
        r.s.settimeout(.25)
        r.req('qSupported'); r.req('?'); r.req('Qqemu.PhyMemMode:1')
        for pc in POINTS:
            assert r.req(f'Z0,{pc:x},4')=='OK'
            installed.add(pc)
        r.send('c'); stopped=False

        def memory(address, size):
            raw=r.req(f'm{address:x},{size:x}')
            if raw.startswith('E'):raise RuntimeError('Unreadable native observation')
            return bytes.fromhex(raw)

        def pump(seconds):
            nonlocal stopped
            deadline=time.monotonic()+seconds
            while time.monotonic()<deadline:
                if STOP.is_set():raise RuntimeError('Test stopped; artifacts preserved')
                if proc.poll() is not None:raise RuntimeError('Guest exited')
                try:r.recv();stopped=True
                except socket.timeout:continue
                pc=r.reg(64)
                if pc not in installed:raise RuntimeError('Unexpected debugger stop '+hex(pc))
                frame=r.reg(31)
                event={'pc':hex(pc),'name':POINTS[pc],
                       'elapsed':round(time.monotonic()-started,2),'return':r.reg(3)}
                if pc==0x227f7fc:
                    pointers=[int.from_bytes(memory(frame+x,4),'big') for x in (0x5c,0x60)]
                    event.update(web_available=memory(pointers[0],1)[0],
                                 portal_available=memory(pointers[1],1)[0])
                    fields={'SW_OPTION_INTERNET':0x44,'PSA_portal_active':0x45,
                            'Web_active':0x46,'SETUP_FLAG_BT_ACTIVATED':0x4c,
                            'SW_OPTION_BT_DUN':0x4d,'HW_FLAG_SMEG_INT_E':0x4e}
                    event['inputs']={name:memory(frame+offset,1)[0]
                                     for name,offset in fields.items()}
                report['trace'].append(event)
                (out/'trace.json').write_text(json.dumps(report['trace'],indent=2)+'\n')
                assert r.req(f'z0,{pc:x},4')=='OK'
                r.req('s')
                # Bound tracing overhead; observations are sufficient without
                # stopping on every repeated native availability poll.
                if sum(e['pc']==hex(pc) for e in report['trace'])<16:
                    assert r.req(f'Z0,{pc:x},4')=='OK'
                else:installed.remove(pc)
                r.send('c');stopped=False
            if not installed:
                time.sleep(max(0,deadline-time.monotonic()))

        # Observe a rendered native frame instead of waiting an arbitrary
        # three minutes. Then allow native async startup another 15 seconds.
        ready = False
        deadline = started+boot_seconds
        while time.monotonic()<deadline:
            pump(min(5,max(0,deadline-time.monotonic())))
            # Do not ask for display readback during early kernel startup.
            # First require actual native HMI execution, excluding boot logos.
            if not report['trace']:
                continue
            file=out/'boot-probe.png'
            q.call('screendump',{'filename':str(file),'format':'png'})
            with Image.open(file) as im:
                ready=(bool(report['trace']) and im.size==(800,480)
                       and im.convert('RGB').getcolors(1024) is None)
            if ready:break
        if not ready:raise TimeoutError('No rendered native frame before boot deadline')
        report['rendered_frame_after_seconds']=round(time.monotonic()-started,2)
        pump(max(15,60-(time.monotonic()-started)))
        q.call('human-monitor-command',{'command-line':'log unimp,guest_errors'})
        report['debug_logging']='Boot unimp; unimp,guest_errors enabled for UI verification'
        def screenshot(name):
            file=out/(name+'.png')
            q.call('screendump',{'filename':str(file),'format':'png'})
            report['screenshots'][name]=str(file.relative_to(ROOT))
        screenshot('boot')
        # Keep the known default key profile while testing Web and telephone.
        # Switching to the alternate MENU table first can leave subsequent
        # keys interpreted under stale native FP state. MENU is tested last.
        for name in (('menu',) if menu_only else ('web','telephone','menu')):
            panel(q,name);pump(7);screenshot(name)
            if name in ('web','telephone'):
                tap(q,30,230);pump(5);screenshot(name+'-secondary')
        if native_navigation:
            # The real FMUX configuration disables legacy Web/phone keys.
            # Navigate the verified native MENU by touch, retaining A1 only
            # as the virtual panel input; INT_E hardware flags stay intact.
            tap(q,400,215);pump(7);screenshot('connect-apps')
            tap(q,30,230);pump(5);screenshot('connect-apps-secondary')
        report['guest_status']=q.call('query-status')
    except Exception as exc:
        report['error']=repr(exc)
    finally:
        try:
            if r:
                if not stopped:r.s.sendall(b'\x03');r.recv();stopped=True
                for pc in installed:r.req(f'z0,{pc:x},4')
                r.req('D');r.s.close()
            if q:q.call('quit');q.close()
        except (OSError,EOFError,RuntimeError):pass
        try:proc.wait(timeout=8)
        except subprocess.TimeoutExpired:proc.kill();proc.wait()
        report['exit_code']=proc.returncode
        serial=(out/'serial.log').read_text(errors='replace') if (out/'serial.log').exists() else ''
        report['serial_exception_lines']=[l for l in serial.splitlines() if any(
            term in l.lower() for term in ('data access exception','task is suspended','unhandled exception'))]
        report['serial_flag_lines']=[l for l in serial.splitlines() if any(
            term in l for term in ('Web_active','Wifi_active','Smartapps','HW_FLAG_SMEG_INT_E'))][-20:]
        (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({'case':case,'error':report.get('error'),'screenshots':len(report['screenshots']),
                          'native_observations':len(report['trace']),'exit_code':proc.returncode}),flush=True)
    # Check the native saved state after shutdown as well as input injections.
    if 'error' not in report:
        subprocess.run([sys.executable,'emulation/extract_native_volume.py',
                        '--input',str(out/'nand-ui.raw'),'--base-page','103168',
                        '--output',str(out/'after-boot')],cwd=ROOT,check=True,capture_output=True)
        report['flags_after_boot']=verify_stored_flags(out/'after-boot/files/user_data/sqlite')
        report['flags_preserved']=report['flags_after_boot']==report['flags_before_boot']
        (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cases',nargs='+',choices=['baseline','A','B','C','D'],default=['baseline','A','B','C','D'])
    p.add_argument('--workers',type=int,choices=range(1,6),default=1)
    p.add_argument('--boot-seconds',type=int,default=180)
    p.add_argument('--run-id',default='verified')
    p.add_argument('--menu-only',action='store_true')
    p.add_argument('--full-power',action='store_true',help='Normal CPU priority, best-effort I/O, parallel render workers')
    p.add_argument('--native-navigation',action='store_true',help='Touch native MENU Internet tile after the menu capture')
    a=p.parse_args()
    os.setpriority(os.PRIO_PROCESS, 0, 0 if a.full_power else 15)
    render_threads=max(1,(os.cpu_count() or 1)//a.workers-1) if a.full_power else 1
    if not a.run_id.isalnum():p.error('Alphanumeric run ID required')
    for sig in (signal.SIGINT,signal.SIGTERM):
        signal.signal(sig,lambda signum,frame:STOP.set())
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.workers) as pool:
        futures={pool.submit(run_case,c,a.boot_seconds,a.run_id,a.menu_only,a.full_power,render_threads,a.native_navigation):c for c in a.cases}
        results={}
        for future in concurrent.futures.as_completed(futures):
            case=futures[future]
            try:results[case]=future.result()
            except Exception as exc:results[case]={'case':case,'error':repr(exc)}
            (BASE/('run-results-'+a.run_id+'.json')).write_text(json.dumps(results,indent=2)+'\n')
            if STOP.is_set():
                for pending in futures:pending.cancel()
    if any(r.get('error') for r in results.values()):sys.exit(1)


if __name__=='__main__':main()
