#!/usr/bin/env python3
"""Bounded local-only matrix using car scalar observations on emulator DBs."""
import argparse
import gzip
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from run_usb_probe import QMP, RSP

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from smeg_db_inf import encode_inf

CASES = {
    'baseline': {},
    'web': {'Web_active': 1},
    'apps': {'Smartapps': 1},
    'wifi': {'Wifi_active': 1},
    'web_apps': {'Web_active': 1, 'Smartapps': 1},
    'all': {'Web_active': 1, 'Smartapps': 1, 'Wifi_active': 1},
    'no_portal': {'PSA_portal_active': 0},
    'no_internet': {'SW_OPTION_INTERNET': 0},
    'no_smartapps_option': {'Smartapps': 1, 'SW_OPTION_SMARTAPPS': 0},
    'no_dun': {'Web_active': 1, 'SW_OPTION_BT_DUN': 0},
}


def trace_start(qmp_path, gdb_path, seconds=65):
    q, r = QMP(qmp_path), RSP(gdb_path)
    q.call('stop')
    r.req('qSupported'); r.req('?'); r.req('Qqemu.PhyMemMode:1')
    points = {0x182d338: 'agenda_constructor_flag_store'}
    installed, events = set(), []
    stopped = True
    try:
        for pc in points:
            assert r.req(f'Z0,{pc:x},4') == 'OK'
            installed.add(pc)
        deadline = time.monotonic() + seconds
        while installed and time.monotonic() < deadline:
            r.send('c'); stopped = False
            try:
                r.recv(); stopped = True
            except socket.timeout:
                r.s.sendall(b'\x03'); r.recv(); stopped = True
                continue
            pc = r.reg(64)
            if pc not in installed:
                events.append({'unexpected_stop': hex(pc)}); break
            e = {'pc': hex(pc), 'name': points[pc]}
            def memory(addr, size):
                return bytes.fromhex(r.req(f'm{addr:x},{size:x}'))
            if pc == 0x182d338:
                address = r.reg(29) + 0xba
                e.update(object=hex(r.reg(29)), field=hex(address),
                         value_to_store=r.reg(0), before=memory(address, 1).hex())
            else:
                frame = r.reg(31)
                web = int.from_bytes(memory(frame + 0x5c, 4), 'big')
                portal = int.from_bytes(memory(frame + 0x60, 4), 'big')
                e.update(web_available=memory(web, 1)[0], portal_available=memory(portal, 1)[0],
                         status=int.from_bytes(memory(frame + 8, 4), 'big'))
            assert r.req(f'z0,{pc:x},4') == 'OK'; installed.remove(pc)
            r.req('s')
            if pc == 0x182d338: e['after'] = memory(address, 1).hex()
            events.append(e)
    finally:
        if not stopped: r.s.sendall(b'\x03'); r.recv()
        for pc in installed: r.req(f'z0,{pc:x},4')
        r.req('D'); q.call('cont'); r.s.close(); q.close()
    return events


def panel(q, name):
    keys = {'menu': (0, 2), 'config': (0x17, 2),
            'web': (0x1b, 1), 'telephone': (0x14, 1), 'media': (0x15, 2)}
    variant = 0xa1 if name == 'menu' else 0
    q.call('qom-set', {'path': '/machine', 'property': 'frontpanel-key-variant', 'value': variant})
    time.sleep(.4)
    key, status = keys[name]
    q.call('qom-set', {'path': '/machine', 'property': 'frontpanel-event', 'value': key << 8 | status})


def trace_menu(q, gdb_path):
    """Observe native output booleans after a real front-panel MENU request."""
    r = RSP(gdb_path)
    q.call('qom-set', {'path':'/machine', 'property':'frontpanel-key-variant', 'value':0xa1})
    # The running guest must consume the new FP configuration before the key.
    time.sleep(1)
    q.call('stop')
    r.req('qSupported'); r.req('?'); r.req('Qqemu.PhyMemMode:1')
    pc = 0x227f934
    assert r.req(f'Z0,{pc:x},4') == 'OK'
    events = []
    try:
        q.call('qom-set', {'path':'/machine', 'property':'frontpanel-event', 'value':2})
        deadline = time.monotonic()+12
        while time.monotonic() < deadline:
            r.send('c')
            try: r.recv()
            except socket.timeout:
                r.s.sendall(b'\x03'); r.recv(); continue
            current = r.reg(64)
            if current != pc: break
            frame = r.reg(31)
            def memory(address, size):
                return bytes.fromhex(r.req(f'm{address:x},{size:x}'))
            web = int.from_bytes(memory(frame+0x5c,4),'big')
            portal = int.from_bytes(memory(frame+0x60,4),'big')
            events.append({'pc':hex(pc), 'web_available':memory(web,1)[0],
                           'portal_available':memory(portal,1)[0],
                           'status':int.from_bytes(memory(frame+8,4),'big')})
            break
    finally:
        r.req(f'z0,{pc:x},4'); r.req('D'); q.call('cont')
        r.s.close()
    return events


def tap(q, x, y):
    q.call('input-send-event', {'events': [
        {'type': 'abs', 'data': {'axis': 'x', 'value': round(x*32767/799)}},
        {'type': 'abs', 'data': {'axis': 'y', 'value': round(y*32767/479)}},
        {'type': 'btn', 'data': {'button': 'left', 'down': True}}]})
    time.sleep(.25)
    q.call('input-send-event', {'events': [
        {'type': 'btn', 'data': {'button': 'left', 'down': False}}]})


def trace_browser_attempt(q, gdb_path):
    """Read actual network readiness and native popup after Browser is clicked."""
    r = RSP(gdb_path)
    q.call('stop')
    r.req('qSupported'); r.req('?'); r.req('Qqemu.PhyMemMode:1')
    points = {0x4c8c2f8:'isInternetProfileReady', 0x4c95384:'native_internet_popup'}
    installed = set()
    events = []
    stopped = True
    try:
        for pc in points:
            assert r.req(f'Z0,{pc:x},4') == 'OK'; installed.add(pc)
        r.send('c'); stopped = False
        tap(q,190,210)
        deadline = time.monotonic()+7
        while time.monotonic()<deadline:
            try: r.recv(); stopped = True
            except socket.timeout:
                r.s.sendall(b'\x03'); r.recv(); stopped = True
                r.send('c'); stopped = False; continue
            pc = r.reg(64)
            e = {'pc':hex(pc), 'name':points.get(pc)}
            if pc == 0x4c8c2f8:
                obj = r.reg(3)
                e['object'] = hex(obj)
                e['availability_bytes'] = r.req(f'm{obj+0x51390:x},9')
                e['PPP_state'] = int(r.req(f'm{obj+0x50df8:x},4'),16)
            elif pc == 0x4c95384:
                e.update(popup_id=r.reg(4),popup_context=r.reg(5))
            else: break
            events.append(e)
            r.req(f'z0,{pc:x},4'); r.req('s'); r.req(f'Z0,{pc:x},4')
            if pc == 0x4c95384: break
            r.send('c'); stopped = False
    finally:
        if not stopped: r.s.sendall(b'\x03'); r.recv()
        for pc in installed: r.req(f'z0,{pc:x},4')
        r.req('D'); q.call('cont'); r.s.close()
    return events


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--case', choices=CASES, required=True)
    p.add_argument('--boot-seconds', type=float, default=55)
    a = p.parse_args()
    base = ROOT/'artifacts/phase7/car-settings'
    case = base/'runs'/a.case
    case.mkdir(parents=True, exist_ok=False)
    deploy = case/'deploy'
    shutil.copytree(base/'captured-baseline/deploy', deploy)
    changes = []
    for key, value in CASES[a.case].items():
        db = 'config_options.sqlite' if key.startswith('SW_OPTION_') else 'up_config.sqlite'
        file = deploy/'user_data/sqlite'/db
        raw = gzip.decompress(file.read_bytes())
        c = sqlite3.connect(':memory:'); c.deserialize(raw)
        if db == 'config_options.sqlite':
            before = c.execute('SELECT value FROM sw_option WHERE name=?', (key,)).fetchone()[0]
            n = c.execute('UPDATE sw_option SET value=? WHERE name=?', (value, key)).rowcount
        else:
            before = c.execute("SELECT IntValue FROM UP_Keys WHERE Section='internet' AND Name=? AND Idx=0", (key,)).fetchone()[0]
            n = c.execute("UPDATE UP_Keys SET IntValue=? WHERE Section='internet' AND Name=? AND Idx=0", (value, key)).rowcount
        assert n == 1
        c.commit(); assert c.execute('PRAGMA integrity_check').fetchall() == [('ok',)]
        raw = c.serialize(); c.close()
        stored = gzip.compress(raw, mtime=0)
        file.write_bytes(stored)
        Path(str(file)+'.inf').write_bytes(encode_inf(raw, stored))
        changes.append({'database': db, 'name': key, 'before': before, 'after': value})
    subprocess.run([sys.executable, 'emulation/inject_volume.py',
                    '--input', str(base/'captured-baseline/nand.raw'), '--output', str(case/'nand.raw'),
                    '--source', str(deploy), '--base-page', '220032',
                    '--report', str(case/'injection.json')], cwd=ROOT, check=True, capture_output=True)
    prefix = Path('/tmp')/('smeg-p7-'+a.case)
    for suffix in ('.qmp', '.gdb', '.monitor'):
        path = Path(str(prefix)+suffix)
        if path.exists(): raise RuntimeError('Control socket already exists: '+str(path))
    env = dict(os.environ, SMEG_NAND=str(case/'nand.raw'), SMEG_DISPLAY='none',
               SMEG_SERIAL='file:'+str(case/'serial.log'), SMEG_WINDOW_LOG=str(case/'window.log'),
               SMEG_CONTROL_PREFIX=str(prefix), SMEG_PIN_THREADS='0', LP_NUM_THREADS='4',
               SMEG_USB_MEDIA='', SMEG_SD_MEDIA='', SMEG_BENCH_ECU='1', SMEG_BENCH_VEHICLE='1',
               SMEG_BENCH_BODY_CONFIG='1', SMEG_BENCH_KEY_PROFILE='1', SMEG_BENCH_ECO_OFF='0')
    # No HCI bridge, real radio, host USB passthrough, or external networking.
    for key in list(env):
        if key.startswith(('SMEG_HCI', 'SMEG_BT')): del env[key]
    command = ['bash', 'emulation/launch_ui.sh', '-S', '-D', str(case/'qemu.log'),
               '-rtc', 'base=localtime,clock=host', '-action', 'reboot=reset']
    proc = subprocess.Popen(command, cwd=ROOT, env=env, stdin=subprocess.DEVNULL, start_new_session=True)
    report = {'case': a.case, 'physical_car_access': False, 'changes': changes,
              'baseline': 'Captured car scalars on emulator templates; missing blobs/common keys retained',
              'native_instruction_patch': False, 'screenshots': {}}
    q = None
    try:
        started = time.monotonic()
        while not Path(str(prefix)+'.gdb').exists():
            if proc.poll() is not None: raise RuntimeError('QEMU exited before controls available')
            if time.monotonic()-started > 15: raise TimeoutError('QEMU control startup')
            time.sleep(.1)
        report['native_trace'] = trace_start(str(prefix)+'.qmp', str(prefix)+'.gdb')
        while time.monotonic()-started < a.boot_seconds:
            if proc.poll() is not None: raise RuntimeError('QEMU exited during boot')
            time.sleep(.25)
        q = QMP(str(prefix)+'.qmp')
        for name in ('boot', 'menu', 'web', 'telephone'):
            if name == 'menu':
                report['menu_availability_trace'] = trace_menu(q, str(prefix)+'.gdb')
                time.sleep(4)
            elif name != 'boot': panel(q, name); time.sleep(4)
            path = case/(name+'.png')
            q.call('screendump', {'filename': str(path), 'format': 'png'})
            report['screenshots'][name] = str(path.relative_to(ROOT))
            if name == 'web':
                # Native secondary menu, not a synthetic portal or forced network.
                tap(q, 30, 230); time.sleep(3)
                path = case/'web-secondary.png'
                q.call('screendump', {'filename': str(path), 'format': 'png'})
                report['screenshots']['web-secondary'] = str(path.relative_to(ROOT))
                if CASES[a.case].get('Web_active') == 1 and a.case != 'no_dun':
                    report['browser_attempt_trace'] = trace_browser_attempt(q,str(prefix)+'.gdb')
                    time.sleep(4)
                    path = case/'browser-attempt.png'
                    q.call('screendump', {'filename':str(path), 'format':'png'})
                    report['screenshots']['browser-attempt'] = str(path.relative_to(ROOT))
        report['final_status'] = q.call('query-status')
    except Exception as exc:
        report['error'] = repr(exc)
        raise
    finally:
        try:
            if q is None and proc.poll() is None: q = QMP(str(prefix)+'.qmp')
            if q: q.call('quit')
        except (OSError, EOFError): pass
        if q: q.close()
        try: proc.wait(timeout=8)
        except subprocess.TimeoutExpired: proc.kill(); proc.wait()
        report['exit_code'] = proc.returncode
        serial = (case/'serial.log').read_text(errors='replace') if (case/'serial.log').exists() else ''
        report['serial_exception_lines'] = [line for line in serial.splitlines()
                                            if any(x in line.lower() for x in ('data access exception', 'task is suspended', 'unhandled exception'))]
        (case/'result.json').write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps(report), flush=True)


if __name__ == '__main__': main()
