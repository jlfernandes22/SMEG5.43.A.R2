#!/usr/bin/env python3
"""Bound one existing private emulator; never start a second QEMU."""
import argparse,json,time
from pathlib import Path
from run_usb_probe import QMP

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--pid',type=int,required=True);p.add_argument('--prefix',required=True)
p.add_argument('--directory',type=Path,required=True);p.add_argument('--seconds',type=int,default=10800)
a=p.parse_args();root=Path(__file__).resolve().parents[1]
assert a.directory.resolve().is_relative_to(root/'artifacts/phase8/usb-maintenance/runs')
assert a.prefix.startswith('/tmp/smeg-p8-') and 1<=a.seconds<=10800
cmd=Path(f'/proc/{a.pid}/cmdline').read_bytes()
assert b'qemu-system-ppc' in cmd and str(a.directory.resolve()/'nand.raw').encode() in cmd
out=a.directory/'adopted-supervision.json';assert not out.exists()
j={'qemu_pid':a.pid,'new_QEMU_started':False,'physical_device_access':False,'started_unix':time.time(),'status':'armed'}
out.write_text(json.dumps(j,indent=2)+'\n')
deadline=time.monotonic()+a.seconds
try:
    while time.monotonic()<deadline and not (a.directory/'STOP').exists():
        try:
            if Path(f'/proc/{a.pid}/cmdline').read_bytes()!=cmd:break
        except FileNotFoundError:break
        time.sleep(.25)
    if Path(a.prefix+'.qmp').exists():
        q=QMP(a.prefix+'.qmp')
        try:
            q.call('screendump',{'filename':str((a.directory/'supervision-final.png').resolve()),'format':'png'})
            q.call('quit')
        finally:q.close()
    j['status']='stopped_on_request' if (a.directory/'STOP').exists()else'ended_or_time_bound_reached'
except Exception as e:j.update(status='supervisor_error',error=repr(e))
finally:
    j['ended_unix']=time.time();out.write_text(json.dumps(j,indent=2)+'\n')
