#!/usr/bin/env python3
"""Run an experimental module from virtual USB; never accesses a physical device."""
import argparse
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from run_usb_probe import QMP

ROOT=Path(__file__).resolve().parents[1]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--tag',required=True)
    p.add_argument('--seed',type=Path,required=True)
    p.add_argument('--usb',type=Path,required=True)
    p.add_argument('--audio-256',action='store_true')
    p.add_argument('--native-memory',action='store_true',help='Execute original guest memory routines and module memory routines without host acceleration')
    p.add_argument('--ram-mib',type=int,choices=[256,512],default=512)
    p.add_argument('--boot-seconds',type=int,default=70)
    p.add_argument('--check-internet',action='store_true')
    p.add_argument('--trace-network',action='store_true',help='Observe native Internet/Bluetooth gates after the USB module using read-only breakpoints')
    p.add_argument('--trace-before-usb',action='store_true',help='Read-only cold-boot network observation before hot-plugging the virtual USB')
    p.add_argument('--touch-usb-probe',action='store_true',
                   help='After opening Apps, touch the diagnostic HTML button on the virtual USB')
    p.add_argument('--browser-settle-seconds',type=int,default=4,
                   help='Bounded delay for deferred diagnostic browser probes')
    p.add_argument('--interactive-seconds',type=int,default=0,
                   help='Keep this isolated VM available briefly for direct native UI inspection after screenshots')
    p.add_argument('--usb-at-boot',action='store_true')
    p.add_argument('--stationary',action='store_true',help='Before virtual USB hotplug, send ordinary parked-vehicle and function-availability CAN fixtures')
    p.add_argument('--boot-info-frame', help='Set the simulated local0f vehicle information before CPU start, preserving the chosen car language')
    p.add_argument('--mcu-sw-release', help='Explicit virtual MCU release xx.xx.xx; not measured car data')
    p.add_argument('--mcu-upg-config', help='Explicit16byte virtual MCU UPG fixture as32hex digits')
    p.add_argument('--mcu-system-config', help='Explicit16byte virtual MCU system fixture as32hex digits')
    p.add_argument('--post-insert-seconds',type=int,default=22)
    p.add_argument('--wait-marker',help='Observe a native serial marker before ending the bounded post-insertion wait')
    p.add_argument('--abort-marker',help='Stop and capture evidence if this failure marker appears in the same completion channel')
    p.add_argument('--usb-completion-log',help='Read completion text from this path on the virtual USB instead of the interleaved serial console')
    p.add_argument('--usb-checkpoint-log',help='Capture distinct short virtual-USB status values while the guest runs')
    p.add_argument('--periodic-screenshot-seconds',type=int,default=0,
                   help='Capture bounded native UI frames during work, at intervals of2..120seconds;0 disables')
    p.add_argument('--completion-settle-seconds',type=int,default=5,
                   help='Allow bounded native rendering time after the completion receipt before screenshots')
    p.add_argument('--acknowledge-completion',action='store_true',
                   help='After recording the final native popup, tap its X and capture the restored UI')
    a=p.parse_args()
    if not 0<=a.completion_settle_seconds<=120:p.error('Completion render delay must be0..120 seconds')
    if a.periodic_screenshot_seconds and not 2<=a.periodic_screenshot_seconds<=120:p.error('Periodic screenshot interval must be0 or2..120seconds')
    if a.acknowledge_completion and not (a.wait_marker and a.usb_completion_log):p.error('Acknowledgement requires an observed virtual USB completion receipt')
    if a.abort_marker and not a.wait_marker:p.error('An abort marker requires a completion wait marker')
    if a.boot_info_frame and not re.fullmatch(r'0f:[0-9a-fA-F]{14}', a.boot_info_frame):p.error('Vehicle frame must be local0f plus seven bytes')
    if a.native_memory and not a.audio_256:p.error('--native-memory requires --audio-256')
    if a.touch_usb_probe and not a.check_internet:p.error('--touch-usb-probe requires --check-internet')
    if not 0<=a.browser_settle_seconds<=60:p.error('Browser delay must be 0..60 seconds')
    if not 0<=a.interactive_seconds<=10800:p.error('Interactive inspection must be 0..10800 seconds')
    if not a.tag.isalnum():p.error('Alphanumeric tag required')
    if a.mcu_sw_release and not re.fullmatch(r'[0-9a-fA-F]{2}\.[0-9a-fA-F]{2}\.[0-9a-fA-F]{2}',a.mcu_sw_release):p.error('Virtual MCU release requires xx.xx.xx')
    for config in (a.mcu_upg_config,a.mcu_system_config):
        if config is not None and not re.fullmatch(r'[0-9a-fA-F]{32}',config):p.error('Virtual MCU config requires32hex digits')
    for f in [a.seed,a.usb]:
        if not f.is_file() or not f.resolve().is_relative_to(ROOT/'artifacts'):p.error('Regular workspace artifact inputs required')
    out=ROOT/'artifacts/phase8/usb-maintenance/runs'/a.tag
    out.mkdir(parents=True,exist_ok=False)
    subprocess.run(['cp','--reflink=auto',str(a.seed),str(out/'nand.raw')],check=True)
    prefix='/tmp/smeg-p8-'+a.tag
    env={k:v for k,v in os.environ.items() if not k.startswith('SMEG_')}
    env.update(SMEG_NAND=str(out/'nand.raw'),SMEG_DISPLAY='none',SMEG_PIN_THREADS='0',
             SMEG_CONTROL_PREFIX=prefix,SMEG_SERIAL='file:'+str(out/'serial.log'),
             SMEG_WINDOW_LOG=str(out/'window.log'),SMEG_USB_MEDIA=str(a.usb.resolve()),
             SMEG_USB_HOTPLUG='0' if a.usb_at_boot else '1',SMEG_USB_WORKING_MEDIA=str(out/'usb.raw'),SMEG_SD_MEDIA='',
             SMEG_BENCH_ECU='1',SMEG_BENCH_VEHICLE='1',SMEG_BENCH_KEY_PROFILE='1',LP_NUM_THREADS='2',
             SMEG_RAM_SIZE=str(a.ram_mib)+'M')
    if a.mcu_sw_release:env['SMEG_BENCH_MCU_RELEASE']=a.mcu_sw_release
    if a.mcu_upg_config:env['SMEG_BENCH_MCU_UPG_CONFIG']=a.mcu_upg_config
    if a.mcu_system_config:env['SMEG_BENCH_MCU_SYSTEM_CONFIG']=a.mcu_system_config
    if a.audio_256:
        env.update(SMEG_KERNEL=str(ROOT/'artifacts/phase2/package/SMEG_PLUS_UPG/BSP/SMEG_PLUS_256/vxWorks.bin'),
                   SMEG_APP_VARIANT='audio_bt',SMEG_BSP_VARIANT='256',
                   SMEG_BENCH_HW_PROFILE='int_e',
                    SMEG_FAST_MEM='0' if a.native_memory else '1',
                    SMEG_FAST_MODULE_MEM='0' if a.native_memory else '1')
    proc=subprocess.Popen(['bash','emulation/launch_ui.sh','-D',str(out/'qemu.log'),
                           '-rtc','base=localtime,clock=host','-action','reboot=reset'] + (['-S'] if a.boot_info_frame else []),cwd=ROOT,
                          env=env,stdin=subprocess.DEVNULL,start_new_session=True)
    q=None
    result={'audio_256':a.audio_256,'physical_device_access':False,
            'native_memory_requested':a.native_memory,
            'host_memory_routine_acceleration':bool(a.audio_256 and not a.native_memory),
            'host_module_memory_acceleration':bool(a.audio_256 and not a.native_memory),
            'emulated_RAM_MiB':a.ram_mib,
            'virtual_MCU_release':a.mcu_sw_release,'virtual_MCU_release_is_measured_car_data':False,
            'virtual_MCU_UPG_config':a.mcu_upg_config,'virtual_MCU_system_config':a.mcu_system_config,
            'virtual_MCU_configs_are_measured_car_data':False}
    try:
        if a.boot_info_frame:
            ready=time.monotonic()+15
            while not Path(prefix+'.qmp').exists() and time.monotonic()<ready:
                if proc.poll() is not None:raise RuntimeError('Guest exited before board configuration')
                time.sleep(.1)
            q=QMP(prefix+'.qmp')
            q.call('qom-set',{'path':'/machine','property':'bench-can','value':a.boot_info_frame})
            q.call('cont');q.close();q=None
            result['ordinary_vehicle_information_before_boot']=a.boot_info_frame
        deadline=time.monotonic()+a.boot_seconds
        while time.monotonic()<deadline:
            if proc.poll() is not None:raise RuntimeError('Guest exited during boot')
            time.sleep(.25)
        q=QMP(prefix+'.qmp')
        q.call('screendump',{'filename':str(out/'before-usb.png'),'format':'png'})
        if a.trace_before_usb:
            if not a.audio_256 or a.usb_at_boot:raise ValueError('Cold observer requires AUDIO_BT_256 and later hotplug')
            q.close();q=None
            subprocess.run(['python3','emulation/trace_usb_network_ui.py','--prefix',prefix,
                '--output',str(out/'cold-network-trace')],cwd=ROOT,check=True,timeout=140)
            q=QMP(prefix+'.qmp')
        if a.stationary:
            if a.usb_at_boot:raise ValueError('Stationary pre-insertion fixture requires later virtual hotplug')
            fixtures=('15:0000000000000080',a.boot_info_frame or '0f:00040000000000')
            for fixture in fixtures:
                q.call('qom-set',{'path':'/machine','property':'bench-can','value':fixture})
            result['pre_insertion_parked_vehicle_fixtures']=list(fixtures)
        result['usb_attach']=('at_boot' if a.usb_at_boot else q.call('device_add',{'driver':'usb-storage','id':'testusb','drive':'benchmedia','removable':True}))
        post_deadline=time.monotonic()+a.post_insert_seconds
        inserted_at=time.monotonic();periodic_next=inserted_at+a.periodic_screenshot_seconds
        serial_offset=0;serial_tail='';result['wait_marker_seen']=False
        checkpoint_seen=set();checkpoint_pending=None;checkpoint_next=0
        while time.monotonic()<post_deadline:
            if proc.poll() is not None:raise RuntimeError('Guest exited after USB insertion')
            if (a.periodic_screenshot_seconds and time.monotonic()>=periodic_next
                    and len(result.get('periodic_screenshots',[]))<256):
                path=out/('progress-frame-%03d.png'%len(result.get('periodic_screenshots',[])))
                q.call('screendump',{'filename':str(path),'format':'png'})
                result.setdefault('periodic_screenshots',[]).append(dict(
                    elapsed_seconds=round(time.monotonic()-inserted_at,3),screenshot=str(path)))
                (out/'progress-frames.json').write_text(json.dumps(result['periodic_screenshots'],indent=2)+'\n')
                periodic_next=time.monotonic()+a.periodic_screenshot_seconds
            if a.usb_checkpoint_log and time.monotonic()>=checkpoint_next:
                checkpoint_next=time.monotonic()+1
                check=subprocess.run(['mtype','-i',str(out/'usb.raw')+'@@1048576',
                    '::/'+a.usb_checkpoint_log.lstrip('/')],capture_output=True,
                    env=dict(os.environ,MTOOLS_SKIP_CHECK='1'),timeout=3)
                value=check.stdout.decode('ascii',errors='replace').strip()
                if check.returncode==0 and value and len(value)<=256 and value not in checkpoint_seen and len(checkpoint_seen)<64:
                    checkpoint_seen.add(value);checkpoint_pending=(value,time.monotonic())
            if checkpoint_pending and time.monotonic()-checkpoint_pending[1]>=2:
                value,_=checkpoint_pending;checkpoint_pending=None
                path=out/('checkpoint-%02d.png'%len(result.get('checkpoints',[])))
                q.call('screendump',{'filename':str(path),'format':'png'})
                result.setdefault('checkpoints',[]).append(dict(status=value,screenshot=str(path)))
                (out/'checkpoints.json').write_text(json.dumps(result['checkpoints'],indent=2)+'\n')
            if a.wait_marker:
                if a.usb_completion_log:
                    receipt=subprocess.run(['mtype','-i',str(out/'usb.raw')+'@@1048576',
                        '::/'+a.usb_completion_log.lstrip('/')],capture_output=True,text=True,
                        env=dict(os.environ,MTOOLS_SKIP_CHECK='1'),timeout=3)
                    serial_tail=receipt.stdout
                    result['completion_channel']='virtual_USB_receipt'
                else:
                    with (out/'serial.log').open('r',errors='replace') as log:
                        log.seek(serial_offset);chunk=log.read();serial_offset=log.tell()
                    serial_tail=(serial_tail+chunk)[-2048:]
                if a.abort_marker and a.abort_marker in serial_tail:
                    q.call('screendump',{'filename':str(out/'after-usb.png'),'format':'png'})
                    raise RuntimeError('Native USB failure receipt: '+serial_tail[:512])
                if a.wait_marker in serial_tail:
                    result['wait_marker_seen']=True
                    time.sleep(a.completion_settle_seconds)
                    break
            time.sleep(.25)
        if a.wait_marker and not result['wait_marker_seen']:
            raise TimeoutError('Native USB completion marker not observed')
        q.call('screendump',{'filename':str(out/'after-usb.png'),'format':'png'})
        if a.acknowledge_completion:
            q.call('input-send-event',{'events':[
                {'type':'abs','data':{'axis':'x','value':round(224*32767/799)}},
                {'type':'abs','data':{'axis':'y','value':round(75*32767/479)}},
                {'type':'btn','data':{'button':'left','down':True}}]})
            time.sleep(.2)
            q.call('input-send-event',{'events':[{'type':'btn','data':{'button':'left','down':False}}]})
            time.sleep(10)
            q.call('screendump',{'filename':str(out/'after-completion-ack.png'),'format':'png'})
            result['completion_popup_acknowledged']=True
        if a.trace_network:
            if not a.audio_256:raise ValueError('Network observer supports exact AUDIO_BT_256 only')
            q.close();q=None
            subprocess.run(['python3','emulation/trace_usb_network_ui.py','--prefix',prefix,
                '--output',str(out/'network-trace')],cwd=ROOT,check=True,timeout=140)
            q=QMP(prefix+'.qmp')
        if a.check_internet:
            if a.audio_256:
                variant=q.call('qom-get',{'path':'/machine','property':'frontpanel-key-variant'})
                menu_key=(1 if variant==0xa1 else 0)
                q.call('qom-set',{'path':'/machine','property':'frontpanel-event',
                    'value':(menu_key<<8)|1})
                time.sleep(.8)
                q.call('qom-set',{'path':'/machine','property':'frontpanel-event',
                    'value':(menu_key<<8)|2})
                time.sleep(2)
                q.call('screendump',{'filename':str(out/'main-menu.png'),'format':'png'})
                q.call('input-send-event',{'events':[
                    {'type':'abs','data':{'axis':'x','value':round(400*32767/799)}},
                    {'type':'abs','data':{'axis':'y','value':round(215*32767/479)}},
                    {'type':'btn','data':{'button':'left','down':True}}]})
                time.sleep(.18)
                q.call('input-send-event',{'events':[{'type':'btn','data':{'button':'left','down':False}}]})
            else:
                q.call('qom-set',{'path':'/machine','property':'frontpanel-key-variant','value':0})
                time.sleep(.5)
                q.call('qom-set',{'path':'/machine','property':'frontpanel-event','value':0x1b01})
            time.sleep(4)
            q.call('screendump',{'filename':str(out/'connect-apps.png'),'format':'png'})
            q.call('input-send-event',{'events':[
                {'type':'abs','data':{'axis':'x','value':round(30*32767/799)}},
                {'type':'abs','data':{'axis':'y','value':round(230*32767/479)}},
                {'type':'btn','data':{'button':'left','down':True}}]})
            time.sleep(.25)
            q.call('input-send-event',{'events':[{'type':'btn','data':{'button':'left','down':False}}]})
            time.sleep(a.browser_settle_seconds)
            q.call('screendump',{'filename':str(out/'internet.png'),'format':'png'})
            if a.touch_usb_probe:
                q.call('input-send-event',{'events':[
                    {'type':'abs','data':{'axis':'x','value':round(200*32767/799)}},
                    {'type':'abs','data':{'axis':'y','value':round(230*32767/479)}},
                    {'type':'btn','data':{'button':'left','down':True}}]})
                time.sleep(.2)
                q.call('input-send-event',{'events':[{'type':'btn','data':{'button':'left','down':False}}]})
                time.sleep(4)
                q.call('screendump',{'filename':str(out/'usb-page-touch.png'),'format':'png'})
                result['usb_probe_touch_sent']=True
        result['guest_status']=q.call('query-status')
        if a.interactive_seconds:
            result.update(inspection_active=True,qmp_socket=prefix+'.qmp',qemu_pid=proc.pid)
            (out/'inspection-ready.json').write_text(json.dumps(result,indent=2)+'\n')
            print(json.dumps({'inspection_ready':True,'socket':prefix+'.qmp','seconds':a.interactive_seconds}),flush=True)
            q.close();q=None
            deadline=time.monotonic()+a.interactive_seconds
            while time.monotonic()<deadline and proc.poll() is None and not (out/'STOP').exists():time.sleep(.25)
            if proc.poll() is None:q=QMP(prefix+'.qmp')
            result['inspection_active']=False
    except Exception as e:
        result['error']=repr(e);raise
    finally:
        try:
            if q is None and proc.poll() is None:q=QMP(prefix+'.qmp')
            if q:q.call('quit')
        except (OSError,EOFError):pass
        if q:q.close()
        try:proc.wait(timeout=8)
        except subprocess.TimeoutExpired:proc.kill();proc.wait()
        result['returncode']=proc.returncode
        (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(result),flush=True)


if __name__=='__main__':main()
