#!/usr/bin/env python3
"""Cold-boot a saved NAND image, with no USB or RAM patches.

This is an additional application control. It is NOT native USB installation
evidence; that separate test must pass before any deployment claim.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time
from run_usb_probe import QMP

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--nand', type=Path, required=True)
    p.add_argument('--tag', required=True)
    p.add_argument('--boot-seconds', type=int, default=100)
    p.add_argument('--settle-seconds', type=int, default=7)
    p.add_argument('--inspection-seconds', type=int, default=0)
    p.add_argument('--trace-render', action='store_true')
    p.add_argument('--ram-mib',type=int,choices=[256,512],default=512)
    p.add_argument('--native-source-audit',type=Path,
                   help='Separate stopped native-updater storage audit matching this exact source NAND')
    a = p.parse_args()
    assert a.tag.isalnum() and 10 <= a.boot_seconds <= 600
    assert 1 <= a.settle_seconds <= 60 and 0 <= a.inspection_seconds <= 600
    assert a.nand.resolve().is_relative_to(ROOT / 'artifacts') and a.nand.is_file()
    if a.native_source_audit:
        assert a.native_source_audit.resolve().is_relative_to(ROOT/'artifacts/phase13')
        evidence=json.loads(a.native_source_audit.read_text())
        assert (ROOT/evidence['nand']).resolve()==a.nand.resolve()
        assert evidence['stored_candidate_bytes_and_databases_verified']
    out = ROOT / 'artifacts/phase13' / ('disk-control-' + a.tag)
    out.mkdir(exist_ok=False)
    subprocess.run(['cp', '--reflink=auto', str(a.nand), str(out / 'nand.raw')], check=True)
    prefix = '/tmp/smeg-p8-' + a.tag
    env = {k: v for k, v in os.environ.items() if not k.startswith('SMEG_')}
    env.update(SMEG_NAND=str(out / 'nand.raw'), SMEG_DISPLAY='none', SMEG_PIN_THREADS='0',
        SMEG_CONTROL_PREFIX=prefix, SMEG_SERIAL='file:' + str(out / 'serial.log'),
        SMEG_WINDOW_LOG=str(out / 'window.log'), SMEG_BENCH_ECU='1', SMEG_BENCH_VEHICLE='1',
        SMEG_BENCH_KEY_PROFILE='1', LP_NUM_THREADS='2', SMEG_KERNEL=str(ROOT / 'artifacts/phase2/package/SMEG_PLUS_UPG/BSP/SMEG_PLUS_256/vxWorks.bin'),
        SMEG_APP_VARIANT='audio_bt', SMEG_BSP_VARIANT='256', SMEG_BENCH_HW_PROFILE='int_e',
        SMEG_FAST_MEM='1',SMEG_RAM_SIZE=str(a.ram_mib)+'M')
    if a.trace_render:
        env['SMEG_TRACE_GL_TIMING'] = '1'
    proc = subprocess.Popen(['bash', 'emulation/launch_ui.sh', '-D', str(out / 'qemu.log')], cwd=ROOT, env=env)
    q = observer = None
    result = {'offline_disk_control_only': a.native_source_audit is None,
              'source_native_storage_audit':str(a.native_source_audit)if a.native_source_audit else None,
              'native_USB_installation_verified': False,
              'emulated_RAM_MiB':a.ram_mib,
              'guest_RAM_patches': False, 'USB_attached': False, 'physical_devices_accessed': False,
              'screenshots': [], 'policy_observer': str(out / 'dun-policy.json')}
    try:
        deadline = time.monotonic() + 20
        while not Path(prefix + '.qmp').exists():
            if proc.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError('Cold-boot control did not start')
            time.sleep(.1)
        observer = subprocess.Popen(['python3', 'emulation/trace_persistent_dun_policy.py',
            '--prefix', prefix, '--output', str(out / 'dun-policy.json'), '--seconds', str(a.boot_seconds + 60)],
            cwd=ROOT, stdout=open(out / 'observer.log', 'wb'), stderr=subprocess.STDOUT)
        # A QMP chardev serves one client. Let the observer finish arming its
        # read-only hardware breakpoints and release QMP before UI capture.
        arm_deadline = time.monotonic() + 25
        while observer.poll() is None:
            report = out / 'dun-policy.json'
            if report.exists():
                state = json.loads(report.read_text())
                if state.get('hardware_debug_breakpoints'):
                    time.sleep(.3)
                    break
            if time.monotonic() > arm_deadline:
                raise RuntimeError('Policy observer did not finish arming')
            time.sleep(.1)
        time.sleep(a.boot_seconds)
        def command(name, args=None):
            connection = QMP(prefix + '.qmp')
            try:
                return connection.call(name, args)
            finally:
                connection.close()
        def screenshot(name):
            path = out / (name + '.png')
            command('screendump', {'filename': str(path), 'format': 'png'})
            result['screenshots'].append(str(path))
        def tap(x, y):
            command('input-send-event', {'events': [
                {'type': 'abs', 'data': {'axis': 'x', 'value': round(x * 32767 / 799)}},
                {'type': 'abs', 'data': {'axis': 'y', 'value': round(y * 32767 / 479)}},
                {'type': 'btn', 'data': {'button': 'left', 'down': True}}]})
            time.sleep(.18)
            command('input-send-event', {'events': [{'type': 'btn', 'data': {'button': 'left', 'down': False}}]})
        screenshot('boot')
        variant = command('qom-get', {'path': '/machine', 'property': 'frontpanel-key-variant'})
        def menu():
            key = 1 if variant == 0xa1 else 0
            command('qom-set', {'path': '/machine', 'property': 'frontpanel-event',
                'value': (key << 8) | 1})
            time.sleep(.15)
            command('qom-set', {'path': '/machine', 'property': 'frontpanel-event',
                'value': (key << 8) | 2})
            # The selector is transient. Capture/select promptly rather than
            # spending the application-settle interval on this overlay.
            time.sleep(min(.75, a.settle_seconds))
        menu()
        screenshot('menu')
        tap(555, 215)
        time.sleep(a.settle_seconds)
        screenshot('phone')
        menu()
        tap(400, 215)
        time.sleep(a.settle_seconds)
        screenshot('connect-apps')
        tap(30, 230)
        time.sleep(a.settle_seconds)
        screenshot('internet')
        time.sleep(20)
        screenshot('internet-after-wait')
        result['guest_status'] = command('query-status')
        if a.inspection_seconds:
            (out / 'inspection-ready.json').write_text(json.dumps({
                'qmp_prefix': prefix, 'seconds': a.inspection_seconds,
                'RAM_patches': False, 'native_USB_installation': False}, indent=2) + '\n')
            deadline = time.monotonic() + a.inspection_seconds
            while time.monotonic() < deadline and proc.poll() is None:
                if (out / 'STOP').exists():
                    break
                time.sleep(.25)
    except Exception as error:
        result['error'] = repr(error)
    finally:
        if q:
            q.close()
            q = None
        if observer and observer.poll() is None:
            # Let its bounded trace remove breakpoints and detach first.
            try:
                observer.wait(timeout=max(5, a.boot_seconds + 65))
            except subprocess.TimeoutExpired:
                observer.terminate()
                observer.wait(timeout=5)
        if proc.poll() is None:
            try:
                q = QMP(prefix + '.qmp')
                q.call('quit')
            except (OSError, EOFError):
                pass
            finally:
                if q:
                    q.close()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        result['exit_code'] = proc.returncode
        result['serial_exception_lines'] = [line for line in (out / 'serial.log').read_text(errors='replace').splitlines()
            if any(s in line.lower() for s in ['data access exception', 'task is suspended', 'unhandled exception'])]
        (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
