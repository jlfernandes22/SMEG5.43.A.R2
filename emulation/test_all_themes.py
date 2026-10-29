#!/usr/bin/env python3
"""Private Phase15 QEMU runtime for native theme selection experiments.

No physical USB/Bluetooth/car devices, guest calls or RAM patches. The source
NAND is copied before launch. STOP requests a clean QMP quit. UI screenshots
must be inspected; a settings row alone is not proof of a loadable theme.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
from run_usb_probe import QMP

ROOT = Path(__file__).resolve().parents[1]
PHASE = ROOT/'artifacts/phase15'


def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--nand', type=Path, required=True)
    p.add_argument('--tag', required=True)
    p.add_argument('--seconds', type=int, default=3600)
    p.add_argument('--ram-mib', type=int, choices=(256,512), default=512)
    p.add_argument('--native-memory', action='store_true',
                   help='Execute the guest memory routines instead of host memcpy/memset acceleration')
    p.add_argument('--boot-info-frame', help='Configure ordinary local0f vehicle information before CPU start')
    p.add_argument('--hold-cpu',action='store_true',help='With --boot-info-frame, leave CPU paused for a read-only cold trace')
    p.add_argument('--mcu-sw-release',help='Explicit virtual MCU fixture, not measured car data')
    p.add_argument('--mcu-upg-config')
    p.add_argument('--mcu-system-config')
    a = p.parse_args()
    assert not a.boot_info_frame or re.fullmatch(r'0f:[0-9a-fA-F]{14}',a.boot_info_frame)
    assert not a.hold_cpu or a.boot_info_frame
    assert not a.mcu_sw_release or re.fullmatch(r'[0-9a-fA-F]{2}\.[0-9a-fA-F]{2}\.[0-9a-fA-F]{2}',a.mcu_sw_release)
    assert all(not v or re.fullmatch(r'[0-9a-fA-F]{32}',v)for v in (a.mcu_upg_config,a.mcu_system_config))
    source = a.nand.resolve()
    assert source.is_relative_to(ROOT/'artifacts') and source.is_file() and not a.nand.is_symlink()
    assert source.stat().st_size in (276824064,553648128) and re.fullmatch('[A-Za-z0-9]+', a.tag)
    assert source.stat().st_size != 276824064 or a.ram_mib == 256
    assert 120 <= a.seconds <= 7200
    out = PHASE/('runtime-'+a.tag);out.mkdir(exist_ok=False)
    copied = out/'nand.raw'
    before = digest(source)
    subprocess.run(['cp','--reflink=auto','--',str(source),str(copied)],check=True)
    assert digest(copied) == before
    prefix = '/tmp/smeg-p15-'+a.tag
    assert not any(Path(prefix+ext).exists() for ext in ('.qmp','.gdb','.monitor'))
    env = {k:v for k,v in os.environ.items() if not k.startswith('SMEG_')}
    env.update(SMEG_NAND=str(copied),SMEG_DISPLAY='none',SMEG_PIN_THREADS='0',
        SMEG_CONTROL_PREFIX=prefix,SMEG_SERIAL='file:'+str(out/'serial.log'),
        SMEG_WINDOW_LOG=str(out/'window.log'),SMEG_BENCH_ECU='1',SMEG_BENCH_VEHICLE='1',
        SMEG_BENCH_KEY_PROFILE='1',SMEG_BENCH_KEY_VARIANT='a1',LP_NUM_THREADS='2',
        SMEG_KERNEL=str(ROOT/'artifacts/phase2/package/SMEG_PLUS_UPG/BSP/SMEG_PLUS_256/vxWorks.bin'),
        SMEG_APP_VARIANT='audio_bt',SMEG_BSP_VARIANT='256',SMEG_BENCH_HW_PROFILE='int_e',
        SMEG_FAST_MEM='0' if a.native_memory else '1',
        SMEG_FAST_MODULE_MEM='0',SMEG_RAM_SIZE=str(a.ram_mib)+'M')
    if a.mcu_sw_release:env['SMEG_BENCH_MCU_RELEASE']=a.mcu_sw_release
    if a.mcu_upg_config:env['SMEG_BENCH_MCU_UPG_CONFIG']=a.mcu_upg_config
    if a.mcu_system_config:env['SMEG_BENCH_MCU_SYSTEM_CONFIG']=a.mcu_system_config
    result = {'source':str(source),'source_sha256':before,'private_nand':str(copied),
        'physical_devices_accessed':False,'USB_attached':False,'guest_RAM_patches':False,
        'RSP_used':False,'prefix':prefix,'ram_mib':a.ram_mib,'offline_asset_control_only':True,
        'native_installation_tested_here':False,
        'host_memory_routine_acceleration':not a.native_memory,
        'host_module_memory_acceleration':False,
        'host_GLES_bridge_still_enabled':True}
    result['virtual_MCU_fixtures_not_measured_car_data']={'release':a.mcu_sw_release,'upg_config':a.mcu_upg_config,'system_config':a.mcu_system_config}
    (out/'runtime.json').write_text(json.dumps(result,indent=2)+'\n')
    proc = subprocess.Popen(['bash','emulation/launch_ui.sh','-D',str(out/'qemu.log'),
                             '-action','reboot=reset'] + (['-S'] if a.boot_info_frame else []),cwd=ROOT,env=env)
    try:
        if a.boot_info_frame:
            ready=time.monotonic()+15
            while not Path(prefix+'.qmp').exists() and time.monotonic()<ready:
                if proc.poll() is not None:raise RuntimeError('Guest exited before board configuration')
                time.sleep(.1)
            q=QMP(prefix+'.qmp')
            try:
                q.call('qom-set',{'path':'/machine','property':'bench-can','value':a.boot_info_frame})
                if not a.hold_cpu:q.call('cont')
            finally:q.close()
            result['ordinary_vehicle_information_before_boot']=a.boot_info_frame
        deadline = time.monotonic()+a.seconds
        while proc.poll() is None and time.monotonic()<deadline and not (out/'STOP').exists():
            time.sleep(.25)
    finally:
        if proc.poll() is None:
            try:
                q = QMP(prefix+'.qmp');q.call('quit');q.close()
            except (OSError,EOFError):
                proc.terminate()
        try:proc.wait(timeout=10)
        except subprocess.TimeoutExpired:proc.kill();proc.wait()
        result.update(exit_code=proc.returncode,source_unchanged=digest(source)==before,
                      stopped_nand_sha256=digest(copied))
        serial = (out/'serial.log').read_text(errors='replace') if (out/'serial.log').exists() else ''
        result['serial_exception_lines'] = [s for s in serial.splitlines() if
            any(x in s.lower() for x in ('data access exception','task is suspended','unhandled exception'))]
        (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(result),flush=True)


if __name__ == '__main__':
    main()
