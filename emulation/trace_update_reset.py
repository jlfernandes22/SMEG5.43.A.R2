#!/usr/bin/env python3
"""Observe native reboot callers in a private QEMU; no injected guest calls."""
import argparse,json,time,struct
from pathlib import Path
from run_usb_probe import QMP,RSP
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--directory',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--seconds',type=int,default=65);a=p.parse_args()
q=QMP(a.directory/'control.qmp');q.call('stop');r=RSP(a.directory/'control.gdb');r.req('qSupported');r.req('?');r.req('Qqemu.PhyMemMode:1');pc=0x20e3d0;assert r.req(f'Z0,{pc:x},4')=='OK';q.close();stopped=True
report={'firmware_patched':False,'physical_car_access':False,'events':[]}
try:
 end=time.monotonic()+a.seconds
 while time.monotonic()<end and len(report['events'])<3:
  r.send('c');stopped=False
  try:r.recv();stopped=True
  except TimeoutError:r.s.sendall(b'\x03');r.recv();stopped=True;continue
  actual=r.reg(64)
  if actual!=pc:report['unexpected_stop']=hex(actual);break
  item={'pc':hex(actual),'r3':hex(r.reg(3)),'lr':hex(r.reg(67)),'frames':[]};sp=r.reg(1)
  for _ in range(24):
   if not 0x1000<sp<0x1ffffff0:break
   raw=r.req(f'm{sp:x},8')
   if raw.startswith('E'):break
   prev,lr=struct.unpack('>II',bytes.fromhex(raw));item['frames'].append({'sp':hex(sp),'lr':hex(lr)})
   if not sp<prev<sp+0x20000:break
   sp=prev
  report['events'].append(item);a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(item),flush=True)
  r.req(f'z0,{pc:x},4');r.req('s');r.req(f'Z0,{pc:x},4')
finally:
 if not stopped:r.s.sendall(b'\x03');r.recv()
 r.req(f'z0,{pc:x},4');r.req('D');r.s.close();q=QMP(a.directory/'control.qmp');q.call('cont');q.close();report['guest_resumed']=True;a.output.write_text(json.dumps(report,indent=2)+'\n')
