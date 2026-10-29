#!/usr/bin/env python3
"""Bounded native USB insertion trace in a private QEMU/NAND sandbox.
Breakpoints observe original instructions; no guest function calls are injected.
"""
import argparse
from collections import Counter
import json
import os
import re
from pathlib import Path
import shutil
import socket
import subprocess
import time

ROOT = Path(__file__).resolve().parent.parent
POINTS = {
    0x490808: ('open', 'path'), 0x48fd44: ('stat', 'path'),
    0x48fc6c: ('opendir', 'path'), 0x2c7db0: ('fopen', 'path'),
    0x4aad04: ('loadModule', 'execution'), 0x2cb324: ('system', 'execution'),
    0x4c7c80: ('shellExec', 'execution'), 0x4b5650: ('shellInOutRedirectScript', 'execution'),
    0x168f328: ('USB_HandleMountEvent', 'mount'),
    0x188676c: ('UPGRADE_HandleMountEvent', 'mount'),
    0x29ab18: ('Doctor_CheckCRCInf_failed', 'recovery'),
    0x29a728: ('Doctor_CheckCRCInf_passed', 'recovery'),
    0x29ab84: ('Doctor_GetInfLoadInfo_failed', 'recovery'),
    0x29abb8: ('Doctor_native_task_spawn', 'recovery'),
    0x258288: ('BootRomInterruptBootTask', 'recovery'),
    0x29a53c: ('BootRomInterruptBoot', 'recovery'),
    0x1886430: ('CheckIfUpgradeInserted', 'upgrade'),
    0x187699c: ('LoadUpgradePlugin', 'upgrade'),
    0x18778b4: ('CheckTrustedSource', 'upgrade'),
}


class QMP:
    def __init__(self, path):
        self.s = socket.socket(socket.AF_UNIX); self.s.settimeout(5); self.s.connect(str(path))
        self.f = self.s.makefile('rb'); self.f.readline(); self.id = 0
        self.call('qmp_capabilities')

    def call(self, name, args=None):
        self.id += 1; message = {'execute':name, 'id':self.id}
        if args is not None: message['arguments'] = args
        self.s.sendall((json.dumps(message) + '\n').encode())
        while True:
            raw = self.f.readline()
            if not raw: raise EOFError('QMP disconnected')
            reply = json.loads(raw)
            if reply.get('id') == self.id:
                if 'error' in reply: raise RuntimeError(reply['error'])
                return reply.get('return')

    def close(self):
        self.f.close(); self.s.close()


class RSP:
    def __init__(self, path):
        self.s = socket.socket(socket.AF_UNIX); self.s.settimeout(1); self.s.connect(str(path))

    def recv(self):
        while True:
            c = self.s.recv(1)
            if not c: raise EOFError('GDB disconnected')
            if c == b'$': break
        data = bytearray()
        while True:
            c = self.s.recv(1)
            if not c: raise EOFError('GDB disconnected')
            if c == b'#': break
            data.extend(c)
        self.s.recv(2); self.s.sendall(b'+'); return data.decode()

    def send(self, command):
        b = command.encode(); self.s.sendall(b'$' + b + b'#' + f'{sum(b)%256:02x}'.encode())

    def req(self, command):
        self.send(command); return self.recv()

    def reg(self, n): return int(self.req(f'p{n:x}'), 16)

    def string(self, addr):
        if not 0x1000 <= addr < 0x20000000: return None
        data = self.req(f'm{addr:x},100')
        if data.startswith('E'): return None
        raw = bytes.fromhex(data).split(b'\0', 1)[0]
        if raw and all(32 <= b < 127 or b in (9, 10, 13) for b in raw):
            return raw.decode('ascii')
        return None


def trace(qmp, case, output, seconds):
    r = RSP(case / 'control.gdb'); installed = []; stopped = False
    counts, events = Counter(), []
    report = {'physical_device_access':False, 'firmware_patched':False,
              'scope':'Original native calls; breakpoints affect timing; absent events are bounded observations',
              'seconds':seconds, 'events':events}
    checkpoint = time.monotonic()
    try:
        qmp.call('stop'); stopped = True
        r.req('qSupported'); r.req('?'); r.req('Qqemu.PhyMemMode:1')
        for pc in POINTS:
            assert r.req(f'Z0,{pc:x},4') == 'OK'
            installed.append(pc)
        report['qemu_usb_before'] = qmp.call('human-monitor-command', {'command-line':'info usb'})
        report['device_add'] = qmp.call('device_add', {
            'driver':'usb-storage', 'id':'probeusb', 'drive':'benchmedia', 'removable':True})
        started = time.monotonic(); deadline = started + seconds
        while time.monotonic() < deadline:
            r.send('c'); stopped = False
            try:
                stop = r.recv(); stopped = True
            except socket.timeout:
                r.s.sendall(b'\x03'); r.recv(); stopped = True
                continue
            pc = r.reg(64)
            if pc not in POINTS:
                report['unexpected_stop'] = {'pc':hex(pc), 'reply':stop}; break
            name, kind = POINTS[pc]; counts[name] += 1
            event = {'elapsed':round(time.monotonic() - started, 3), 'name':name,
                     'pc':hex(pc), 'lr':hex(r.reg(67))}
            if kind == 'path':
                path = r.string(r.reg(3))
                if path and ('/bd' in path or '/usb' in path.lower()):
                    event['path'] = path; events.append(event)
            else:
                event['r3'] = hex(r.reg(3)); event['r4'] = hex(r.reg(4))
                if kind == 'execution':
                    event['arg3_string'] = r.string(r.reg(3))
                    event['arg4_string'] = r.string(r.reg(4))
                events.append(event)
            if time.monotonic() - checkpoint > 5:
                report['call_counts'] = dict(counts)
                output.write_text(json.dumps(report, indent=2) + '\n')
                checkpoint = time.monotonic()
            if len(events) > 2000: raise RuntimeError('Trace event bound reached')
            assert r.req(f'z0,{pc:x},4') == 'OK'
            r.req('s')
            assert r.req(f'Z0,{pc:x},4') == 'OK'
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        report['qemu_usb_after'] = qmp.call('human-monitor-command', {'command-line':'info usb'})
    finally:
        try:
            if not stopped: r.s.sendall(b'\x03'); r.recv()
            for pc in installed: r.req(f'z0,{pc:x},4')
            r.req('D'); qmp.call('cont')
            report['debugger_cleanup'] = 'Breakpoints removed, detached, guest resumed'
        finally:
            report['call_counts'] = dict(counts)
            output.write_text(json.dumps(report, indent=2) + '\n'); r.s.close()
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode', choices=['baseline','scripts','update','doctor','native','vendor'], required=True)
    p.add_argument('--seconds', type=int, default=55)
    p.add_argument('--boot-seconds', type=int, default=65)
    p.add_argument('--tag', help='Fresh case/result name; defaults to mode')
    p.add_argument('--image', type=Path)
    p.add_argument('--seed', type=Path, default=ROOT/'artifacts/phase4/runs/features/nand.raw')
    p.add_argument('--linger', type=int, default=0)
    a = p.parse_args()
    tag = a.tag or a.mode
    if not re.fullmatch(r'[a-z0-9_]+', tag): p.error('Invalid result tag')
    out = ROOT / 'artifacts/phase5/usb'; case = ROOT / 'artifacts/phase4/runs' / ('usb_probe_' + tag)
    if len(str(case/'control.monitor').encode()) >= 108:
        p.error('Case name too long for Unix sockets; use a shorter --tag')
    case.mkdir(parents=True, exist_ok=True)
    nand = case / 'nand.raw'
    if nand.exists(): p.error('Case already exists; preserve it and choose a fresh run before repeating')
    subprocess.run(['cp','--reflink=auto',str(a.seed),str(nand)], check=True)
    env = dict(os.environ, SMEG_CASE='usb_probe_' + tag, SMEG_DISPLAY='none',
               SMEG_FRONT_PANEL='0', SMEG_USB_HOTPLUG='1', SMEG_SD_MEDIA='',
               SMEG_USB_MEDIA=str(a.image.resolve() if a.image else out/(a.mode+'.raw')))
    proc = subprocess.Popen(['bash','emulation/launch_features.sh'], cwd=ROOT, env=env,
                            stdin=subprocess.DEVNULL, start_new_session=True)
    qmp = None
    try:
        deadline = time.monotonic() + a.boot_seconds
        while time.monotonic() < deadline:
            if proc.poll() is not None: raise RuntimeError('QEMU exited during boot')
            time.sleep(.25)
        qmp = QMP(case/'control.qmp')
        trace(qmp, case, out/(tag+'.trace.json'), a.seconds)
        qmp.call('screendump', {'filename':str(out/(tag+'.png')), 'format':'png'})
        time.sleep(2)
        qmp.close(); qmp = None
        until = time.monotonic() + a.linger
        while proc.poll() is None and time.monotonic() < until:
            time.sleep(.5)
    finally:
        if qmp is None and proc.poll() is None:
            try: qmp = QMP(case/'control.qmp')
            except OSError: pass
        if qmp:
            try: qmp.call('quit')
            except (EOFError, OSError): pass
            qmp.close()
        if proc.poll() is None:
            proc.terminate()
        try: proc.wait(timeout=8)
        except subprocess.TimeoutExpired: proc.kill(); proc.wait()
        serial = case/'factory_db.serial.log'
        if serial.exists(): shutil.copyfile(serial, out/(tag+'.serial.log'))
    print(json.dumps({'mode':a.mode, 'trace':str(out/(tag+'.trace.json')), 'serial':str(out/(tag+'.serial.log'))}))


if __name__ == '__main__': main()
