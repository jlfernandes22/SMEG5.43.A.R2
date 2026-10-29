#!/usr/bin/env python3
"""Observe native Agenda policy stores on a later AUDIO_BT_256 cold boot.

No emulator is started here. QEMU hardware debug breakpoints stop immediately
after the two already-patched stores. No guest functions, register writes or
memory/code writes are issued. An observed false field verifies initialization
only; it does not establish functioning DUN, PAN, Internet or phone connectivity.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import select
import socket
import stat
import time

from run_usb_probe import QMP, RSP

ROOT = Path(__file__).resolve().parents[1]
OUT_ROOT = (ROOT / 'artifacts/phase13').resolve()
APP_BASE = 0x01000000
APP_SHA = 'dc2b3caa0f7d502e6e1956f2a3e7e906732b0da24582c5aff2faa46a7fdeb317'
KERNEL_SHA = 'e8aff17981ae5ba8c1574fba70ed747d32ae08badec932bfae38b7f6a4694110'
SITES = {0x0182d1e0: 'Agenda_C1', 0x0182d4b8: 'Agenda_C2'}
EXPECTED_STORE = bytes.fromhex('997d00ba')
DEFAULT_APP = ROOT / 'artifacts/phase13/binary-analysis/v3/eligibility-agenda/app.bin'
KERNEL = ROOT / 'artifacts/phase2/package/SMEG_PLUS_UPG/BSP/SMEG_PLUS_256/vxWorks.bin'


def offline_guards(app_path):
    """Pin the exact patched Audio binary, kernel and all observed instructions."""
    app_path = app_path.resolve()
    if not app_path.is_relative_to(ROOT / 'artifacts') or not app_path.is_file():
        raise ValueError('Expected a regular local artifact application')
    app, kernel = app_path.read_bytes(), KERNEL.read_bytes()
    if hashlib.sha256(app).hexdigest() != APP_SHA:
        raise ValueError('Exact patched AUDIO_BT_256 application SHA256 mismatch')
    if hashlib.sha256(kernel).hexdigest() != KERNEL_SHA:
        raise ValueError('Original SMEG_PLUS_256 kernel SHA256 mismatch')
    for address in SITES:
        offset = address - APP_BASE
        if app[offset:offset + 4] != EXPECTED_STORE:
            raise ValueError('Missing patched store at ' + hex(address))
        if app[offset - 16:offset] != bytes.fromhex('39600000939d00b4380000013929b580'):
            raise ValueError('Constructor register setup fingerprint mismatch')
    return app, kernel


def validate_prefix(value):
    # Only the private, task-specific Unix control sockets used by this repo.
    if not re.fullmatch(r'/tmp/smeg-[A-Za-z0-9_-]{1,72}', value):
        raise ValueError('Expected private /tmp/smeg-... Unix socket prefix')
    return value


def observe(args, app, kernel, report, checkpoint):
    prefix = validate_prefix(args.prefix)
    socket_deadline = time.monotonic() + args.connect_seconds
    while True:
        paths = [Path(prefix + suffix) for suffix in ('.qmp', '.gdb')]
        if all(path.exists() for path in paths):
            if any(not stat.S_ISSOCK(path.stat().st_mode) for path in paths):
                raise ValueError('Control paths must be Unix sockets')
            break
        if time.monotonic() >= socket_deadline:
            raise TimeoutError('Private QEMU sockets did not become available')
        time.sleep(.1)

    q = r = None
    installed = set()
    stopped = False
    resume_needed = False
    started = time.monotonic()
    first_observation = None

    def memory(address, length):
        if not 0 <= address < 0x20000000 or length <= 0 or address + length > 0x20000000:
            raise ValueError('RAM read outside the bounded guest RAM window')
        reply = r.req(f'm{address:x},{length:x}')
        if reply.startswith('E'):
            raise RuntimeError('Guest memory unavailable at ' + hex(address))
        result = bytes.fromhex(reply)
        if len(result) != length:
            raise RuntimeError('Short guest memory response')
        return result

    def verify_live_application():
        for address, size in [(APP_BASE, 64)] + [(site - 32, 68) for site in SITES]:
            offset = address - APP_BASE
            if memory(address, size) != app[offset:offset + size]:
                raise RuntimeError('Live AUDIO_BT_256 application fingerprint mismatch at ' + hex(address))

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
            raise RuntimeError('QEMU physical RAM observation unavailable')
        if memory(0x00200000, 256) != kernel[:256]:
            raise RuntimeError('Live SMEG_PLUS_256 kernel fingerprint mismatch')
        # Loading can occur later. Hardware debug addresses are safe to arm
        # before application text exists; each event checks the actual text.
        for site in SITES:
            pc = site + 4
            if r.req(f'Z1,{pc:x},4') != 'OK':
                raise RuntimeError('QEMU hardware instruction breakpoint unsupported')
            installed.add(pc)
        report['hardware_debug_breakpoints'] = [hex(pc) for pc in sorted(installed)]
        # QEMU permits one QMP client. Release it before the guest resumes so
        # the independent UI controller can capture the later cold boot.
        q.close()
        q = None
        report['qmp_released_during_observation'] = True
        report['status'] = 'armed_waiting_for_native_stores'
        checkpoint()
        r.send('c')
        stopped = False
        deadline = started + args.seconds
        while time.monotonic() < deadline:
            if first_observation is not None and time.monotonic() - first_observation >= args.settle_seconds:
                break
            ready, _, _ = select.select([r.s], [], [], min(.2, max(0, deadline - time.monotonic())))
            if not ready:
                continue
            try:
                # send('c') may leave its standalone '+' acknowledgement
                # readable before the asynchronous stop packet exists.
                # Consuming that ACK then timing out is normal while running.
                reply = r.recv()
            except socket.timeout:
                continue
            stopped = True
            if not reply.startswith(('S', 'T')):
                raise RuntimeError('Unexpected debugger response: ' + reply[:120])
            pc = r.reg(64)
            if pc not in installed:
                raise RuntimeError('Unexpected guest stop at ' + hex(pc))
            verify_live_application()
            site = pc - 4
            this = r.reg(29)
            if not 0x01000000 <= this <= 0x1fffff00:
                raise RuntimeError('Agenda object outside mapped guest RAM')
            value = memory(this + 0xba, 1)[0]
            event = {'constructor': SITES[site], 'store_address': hex(site),
                     'stop_immediately_after_store': hex(pc), 'executed_instruction': memory(site, 4).hex(),
                     'this_r29': hex(this), 'field_address': hex(this + 0xba),
                     'm_force_no_dun_management': value, 'native_initialized_false': value == 0,
                     'elapsed_seconds': round(time.monotonic() - started, 3)}
            report['events'].append(event)
            if value != 0:
                raise RuntimeError('Native constructor did not initialize the policy byte to false')
            if r.req(f'z1,{pc:x},4') != 'OK':
                raise RuntimeError('Could not remove observed hardware breakpoint')
            installed.remove(pc)
            if first_observation is None:
                first_observation = time.monotonic()
            checkpoint()
            r.send('c')
            stopped = False
            if not installed:
                break
        report['status'] = 'native_policy_false_observed' if report['events'] else 'not_observed_within_bound'
        report['unobserved_constructor_sites'] = [hex(pc - 4) for pc in sorted(installed)]
    except Exception as error:
        report['status'] = 'observer_error'
        report['error'] = repr(error)
    finally:
        cleanup_errors = []
        # Also release QMP after setup failures before touching RSP cleanup.
        if q is not None:
            try:
                q.close()
            except Exception as error:
                cleanup_errors.append('initial QMP close: ' + repr(error))
            q = None
        if r is not None:
            if not stopped:
                try:
                    r.s.sendall(b'\x03')
                    r.recv()
                    stopped = True
                except Exception as error:
                    cleanup_errors.append('interrupt: ' + repr(error))
            for pc in sorted(installed):
                try:
                    if r.req(f'z1,{pc:x},4') != 'OK':
                        raise RuntimeError('Breakpoint removal refused')
                except Exception as error:
                    cleanup_errors.append('remove ' + hex(pc) + ': ' + repr(error))
            try:
                if r.req('D') != 'OK':
                    raise RuntimeError('Debugger detach refused')
                report['debugger_detached'] = True
                report['qemu_detach_resume_requested'] = True
            except Exception as error:
                cleanup_errors.append('detach: ' + repr(error))
            r.s.close()
        if resume_needed:
            try:
                # The UI controller must release its QMP client before it
                # waits for this observer. Each socket operation is bounded.
                q = QMP(prefix + '.qmp')
                q.s.settimeout(5)
                q.call('cont')
                status = q.call('query-status')
                report['final_guest_status'] = status
                report['guest_resumed'] = bool(status.get('running'))
                if not report['guest_resumed']:
                    raise RuntimeError('Guest not running after cleanup resume')
            except Exception as error:
                cleanup_errors.append('resume: ' + repr(error))
            finally:
                if q is not None:
                    q.close()
        report['cleanup_errors'] = cleanup_errors
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        checkpoint()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix')
    parser.add_argument('--app', type=Path, default=DEFAULT_APP)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--seconds', type=int, default=240)
    parser.add_argument('--connect-seconds', type=int, default=30)
    parser.add_argument('--settle-seconds', type=int, default=10)
    parser.add_argument('--offline-check', action='store_true')
    args = parser.parse_args()
    if not args.offline_check and not args.prefix:
        parser.error('--prefix is required for live observation')
    if not 1 <= args.seconds <= 1800 or not 1 <= args.connect_seconds <= 60 or not 0 <= args.settle_seconds <= 60:
        parser.error('Observation/connect/settle bounds exceeded')
    output = args.output.resolve()
    if not output.is_relative_to(OUT_ROOT) or output.exists():
        parser.error('Output must be a new JSON artifact inside artifacts/phase13')
    app, kernel = offline_guards(args.app)
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {'status': 'offline_guards_passed', 'physical_device_access': False,
              'debugger_memory_writes': False, 'debugger_register_writes': False,
              'guest_functions_injected': False, 'guest_code_patched': False,
              'kernel_profile': 'SMEG_PLUS_256', 'application_profile': 'AUDIO_BT_256',
              'app_sha256': APP_SHA, 'kernel_sha256': KERNEL_SHA,
              'expected_native_store': EXPECTED_STORE.hex(),
              'post_store_breakpoints': [hex(site + 4) for site in SITES],
              'events': [], 'offline_only': args.offline_check,
              'interpretation': 'Observes native constructor policy initialization only. Does not verify PAN/DUN/Internet connectivity. C1 and C2 are alternative constructors; either may be unused during a bounded boot.'}

    def checkpoint():
        output.write_text(json.dumps(report, indent=2) + '\n')

    if args.offline_check:
        checkpoint()
    else:
        observe(args, app, kernel, report, checkpoint)
    print(json.dumps({'report': str(output), 'status': report['status'], 'events': len(report['events']),
                      'cleanup_errors': report.get('cleanup_errors', [])}))
    if report['status'] == 'observer_error' or report.get('cleanup_errors'):
        raise SystemExit(1)
    if report['status'] == 'not_observed_within_bound':
        raise SystemExit(3)


if __name__ == '__main__':
    main()
