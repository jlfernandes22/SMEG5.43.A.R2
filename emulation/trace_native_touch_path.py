#!/usr/bin/env python3
"""Bounded, read-only hardware-breakpoint observation of native touchscreen delivery.

Does not start a VM, inject guest calls, write guest memory/registers, or change
firmware. Debug stops and single steps affect timing. Absent events within the
bound do not prove that a native path is unreachable.
"""
import argparse
import hashlib
import json
from pathlib import Path
import select
import socket
import stat
import struct
import time

from run_usb_probe import QMP, RSP
from trace_persistent_dun_policy import (
    ROOT, OUT_ROOT, DEFAULT_APP, APP_BASE, APP_SHA, KERNEL_SHA,
    offline_guards, validate_prefix,
)

SITES = {
    0x01abf560: 'QWSMouseHandler_mouseChanged',
    0x01ab8890: 'QWSServer_sendMouseEvent',
}


def decode_point(data):
    if len(data) != 8:
        raise ValueError('Expected eight QPoint bytes')
    x, y = struct.unpack('>ii', data)
    return dict(x=x, y=y, raw=data.hex())


def observe(args, app, kernel, report, checkpoint):
    prefix = validate_prefix(args.prefix)
    start = time.monotonic()
    until = start + args.connect_seconds
    while True:
        paths = [Path(prefix + suffix) for suffix in ('.qmp', '.gdb')]
        if all(p.exists() for p in paths):
            if any(not stat.S_ISSOCK(p.stat().st_mode) for p in paths):
                raise ValueError('Control endpoints must be private Unix sockets')
            break
        if time.monotonic() >= until:
            raise TimeoutError('Private control sockets unavailable')
        time.sleep(.1)
    q = r = None
    installed = set()
    stopped = False
    resume_needed = False
    last_desktop = None

    def memory(address, length):
        if not 0x1000 <= address < 0x20000000 or not 0 < length <= 256 or address + length > 0x20000000:
            raise ValueError('Read outside bounded guest RAM')
        result = r.req(f'm{address:x},{length:x}')
        if result.startswith('E'):
            raise RuntimeError('Guest memory unavailable at ' + hex(address))
        value = bytes.fromhex(result)
        if len(value) != length:
            raise RuntimeError('Short memory response')
        return value

    def word(address):
        return int.from_bytes(memory(address, 4), 'big')

    def optional_read(address, length):
        try:
            return memory(address, length).hex()
        except (ValueError, RuntimeError) as error:
            return {'unavailable': str(error)}

    def live_guard():
        for address, length in [(APP_BASE, 64)] + [(p, 16) for p in SITES] + [(0x0227f7b4, 4), (0x0182d1e0, 4), (0x0182d4b8, 4)]:
            if memory(address, length) != app[address - APP_BASE:address - APP_BASE + length]:
                raise RuntimeError('Live patched AUDIO_BT_256 fingerprint mismatch at ' + hex(address))
        if memory(0x04c171bc, 4) != bytes.fromhex('38600020'):
            raise RuntimeError('Live segment2 eligibility fingerprint mismatch')

    try:
        q = QMP(prefix + '.qmp')
        q.s.settimeout(5)
        report['initial_guest_status'] = q.call('query-status')
        resume_needed = True
        q.call('stop')
        stopped = True
        r = RSP(prefix + '.gdb')
        r.s.settimeout(5)
        r.req('qSupported')
        r.req('?')
        if r.req('Qqemu.PhyMemMode:1') != 'OK':
            raise RuntimeError('Physical RAM observation unavailable')
        if memory(0x00200000, 256) != kernel[:256]:
            raise RuntimeError('Live kernel fingerprint mismatch')
        for pc in SITES:
            if r.req(f'Z1,{pc:x},4') != 'OK':
                raise RuntimeError('Hardware breakpoint unavailable at ' + hex(pc))
            installed.add(pc)
        q.close()
        q = None
        report['status'] = 'armed_waiting_for_native_touch_events'
        report['qmp_released_during_observation'] = True
        checkpoint()
        r.send('c')
        stopped = False
        deadline = time.monotonic() + args.seconds
        while time.monotonic() < deadline and len(report['events']) < args.max_events:
            if not select.select([r.s], [], [], min(.2, max(0, deadline - time.monotonic())))[0]:
                continue
            try:
                stop = r.recv()
            except socket.timeout:
                continue  # ACK-only readiness is normal while the guest runs.
            stopped = True
            if not stop.startswith(('T', 'S')):
                raise RuntimeError('Unexpected asynchronous debugger reply')
            pc = r.reg(64)
            if pc not in installed:
                raise RuntimeError('Unexpected native debug stop at ' + hex(pc))
            live_guard()
            regs = {n: r.reg(n) for n in (1, 3, 4, 5, 6, 7, 31, 67)}
            event = {'name': SITES[pc], 'pc': hex(pc),
                     'elapsed_seconds': round(time.monotonic() - start, 3),
                     'registers': {str(n): hex(v) for n, v in regs.items()}}
            point_address = regs[4] if pc == 0x01abf560 else regs[3]
            event['point_address'] = hex(point_address)
            event['point'] = decode_point(memory(point_address, 8))
            event['buttons'] = regs[5] if pc == 0x01abf560 else regs[4]
            event['wheel_delta'] = regs[6] if pc == 0x01abf560 else regs[5]
            if pc == 0x01abf560:
                event['handler_this'] = hex(regs[3])
                event['handler_first_48_bytes'] = optional_read(regs[3], 48)
            ctrl = word(0x02f61c8c)
            event['native_ts_controller'] = hex(ctrl)
            if 0x1000 <= ctrl < 0x1ffffc00:
                event['native_calibration_offsets'] = {
                    'x_u16': int.from_bytes(memory(ctrl + 0x3be, 2), 'big'),
                    'y_u16': int.from_bytes(memory(ctrl + 0x3c0, 2), 'big'),
                }
            report['events'].append(event)
            checkpoint()
            # Execute exactly the stopped native instruction with its debug
            # comparator temporarily removed, then re-arm for later inputs.
            if r.req(f'z1,{pc:x},4') != 'OK':
                raise RuntimeError('Could not remove hardware breakpoint')
            installed.remove(pc)
            r.send('s')
            stopped = False
            step = r.recv()
            stopped = True
            if not step.startswith(('T', 'S')):
                raise RuntimeError('Native single-step did not stop normally')
            if r.req(f'Z1,{pc:x},4') != 'OK':
                raise RuntimeError('Could not re-arm hardware breakpoint')
            installed.add(pc)
            r.send('c')
            stopped = False
        report['status'] = 'native_touch_events_observed' if report['events'] else 'not_observed_within_bound'
    except Exception as error:
        report['status'] = 'observer_error'
        report['error'] = repr(error)
    finally:
        errors = []
        if q is not None:
            try:
                q.close()
            except Exception as error:
                errors.append('QMP close: ' + repr(error))
            q = None
        if r is not None:
            if not stopped:
                try:
                    r.s.sendall(b'\x03')
                    r.recv()
                    stopped = True
                except Exception as error:
                    errors.append('interrupt: ' + repr(error))
            for pc in sorted(installed):
                try:
                    if r.req(f'z1,{pc:x},4') != 'OK':
                        raise RuntimeError('Removal refused')
                except Exception as error:
                    errors.append('breakpoint cleanup: ' + repr(error))
            try:
                if r.req('D') != 'OK':
                    raise RuntimeError('Detach refused')
                report['debugger_detached'] = True
            except Exception as error:
                errors.append('detach: ' + repr(error))
            r.s.close()
        if resume_needed:
            try:
                q = QMP(prefix + '.qmp')
                q.s.settimeout(5)
                q.call('cont')
                report['final_guest_status'] = q.call('query-status')
                report['guest_resumed'] = bool(report['final_guest_status'].get('running'))
                if not report['guest_resumed']:
                    raise RuntimeError('Guest remains paused')
            except Exception as error:
                errors.append('resume: ' + repr(error))
            finally:
                if q is not None:
                    q.close()
        report['cleanup_errors'] = errors
        report['elapsed_seconds'] = round(time.monotonic() - start, 3)
        checkpoint()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--prefix', default='/tmp/smeg-p8-nativeMENU34')
    p.add_argument('--app', type=Path, default=DEFAULT_APP)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--seconds', type=int, default=20)
    p.add_argument('--connect-seconds', type=int, default=15)
    p.add_argument('--max-events', type=int, default=128)
    p.add_argument('--offline-check', action='store_true')
    args = p.parse_args()
    if not 1 <= args.seconds <= 60 or not 1 <= args.connect_seconds <= 60 or not 1 <= args.max_events <= 512:
        p.error('Observation bounds exceeded')
    validate_prefix(args.prefix)
    output = args.output.resolve()
    if not output.is_relative_to(OUT_ROOT) or output.exists():
        p.error('Output must be a new artifact under artifacts/phase13')
    app, kernel = offline_guards(args.app)
    for pc in SITES:
        if not APP_BASE <= pc < APP_BASE + len(app):
            p.error('Invalid static trace address')
    report = {'status': 'offline_guards_passed', 'events': [],
              'offline_only': args.offline_check,
              'app_sha256': APP_SHA, 'kernel_sha256': KERNEL_SHA,
              'hardware_debug_sites': {hex(k): v for k, v in SITES.items()},
              'site_fingerprints': {hex(k): app[k - APP_BASE:k - APP_BASE + 16].hex() for k in SITES},
              'physical_device_access': False, 'guest_memory_writes': False,
              'guest_register_writes': False, 'guest_functions_injected': False,
              'firmware_code_patched_by_observer': False,
              'interpretation': 'Native touch-path evidence only; debug stops affect timing. No UI success implied.'}
    output.parent.mkdir(parents=True, exist_ok=True)

    def checkpoint():
        output.write_text(json.dumps(report, indent=2) + '\n')

    if args.offline_check:
        checkpoint()
    else:
        observe(args, app, kernel, report, checkpoint)
    print(json.dumps({'status': report['status'], 'events': len(report['events']), 'report': str(output)}))
    if report['status'] == 'observer_error' or report.get('cleanup_errors'):
        raise SystemExit(1)
    if report['status'] == 'not_observed_within_bound':
        raise SystemExit(3)


if __name__ == '__main__':
    main()
