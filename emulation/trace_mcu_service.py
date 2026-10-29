#!/usr/bin/env python3
"""Observe native reboot callers in a private QEMU; no injected guest calls."""
import argparse,json,time,struct
from pathlib import Path
from run_usb_probe import QMP,RSP
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--directory',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--seconds',type=int,default=65);a=p.parse_args()
q=QMP(a.directory/'control.qmp');q.call('stop');r=RSP(a.directory/'control.gdb');r.req('qSupported');r.req('?');r.req('Qqemu.PhyMemMode:1');points={0x264378:'InitWait_enter',0x2641b8:'Init_enter',0x2642f4:'Init_start_io_return',0x264350:'Init_write_return',0x2643a4:'Init_return',0x263190:'InitEcho_receive',0x26437c:'InitWait_return',0x266858:'LIBCOM_Init_return',0x2662b0:'GetEolHwIdent_return',0x26595c:'EnterEolMode_return',0x26567c:'GetEolSwRelease_return',0x26bd7c:'UPG_Write',0x20e3d0:'sysToMonitor'}
for pc in points:assert r.req(f'Z0,{pc:x},4')=='OK'
q.close();stopped=True
report={'firmware_patched':False,'physical_car_access':False,'events':[]}
try:
 end=time.monotonic()+a.seconds
 while time.monotonic()<end and len(report['events'])<100:
  r.send('c');stopped=False
  try:r.recv();stopped=True
  except TimeoutError:r.s.sendall(b'\x03');r.recv();stopped=True;continue
  actual=r.reg(64)
  if actual not in points:report['unexpected_stop']=hex(actual);break
  pc=actual
  item={'name':points[pc],'pc':hex(actual),'r3':hex(r.reg(3)),'lr':hex(r.reg(67)),'frames':[]};sp=r.reg(1)
  for _ in range(24):
   if not 0x1000<sp<0x1ffffff0:break
   raw=r.req(f'm{sp:x},8')
   if raw.startswith('E'):break
   prev,lr=struct.unpack('>II',bytes.fromhex(raw));item['frames'].append({'sp':hex(sp),'lr':hex(lr)})
   if not sp<prev<sp+0x20000:break
   sp=prev
  item['ticks']=r.req('m867c28,8')
  item['msr']=hex(r.reg(65))
  item['intCnt']=r.req('m866938,4')
  tcb=int(r.req('m867c08,4'),16)
  item['task']=hex(tcb)
  if tcb:
   item['task_context']=r.req(f'm{tcb+0x70:x},70')
  item['registers']={str(n):hex(r.reg(n))for n in [3,4,5,6,30,31]}
  if points[pc]=='InitWait_enter':
   event=r.reg(3);table=int(r.req(f'm{event+4:x},4'),16);sem=int(r.req(f'm{table+r.reg(4)*4:x},4'),16)
   item['event_object']=hex(event);item['semaphore']=hex(sem);item['semaphore_state']=r.req(f'm{sem:x},70')
  if points[pc] in ('Init_enter','Init_return'):
   obj=r.reg(3) if points[pc]=='Init_enter' else r.reg(29)
   item['object']=hex(obj)
   item['state']=r.req(f'm{obj:x},40')
  if points[pc]=='InitEcho_receive':
   item['presentation_state']=r.req(f'm{r.reg(30)+0x2c:x},4')
   item['message']=r.req(f'm{r.reg(31):x},8')
  if points[pc]=='UPG_Write':
   ptr,n=r.reg(4),min(r.reg(5),92)
   if 0x1000<ptr<0x1fffff00:item['buffer']=r.req(f'm{ptr:x},{n:x}')
  report['events'].append(item);a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(item),flush=True)
  r.req(f'z0,{pc:x},4');r.req('s');r.req(f'Z0,{pc:x},4')
finally:
 if not stopped:r.s.sendall(b'\x03');r.recv()
 for pc in points:r.req(f'z0,{pc:x},4')
 r.req('D');r.s.close();q=QMP(a.directory/'control.qmp');q.call('cont');q.close();report['guest_resumed']=True;a.output.write_text(json.dumps(report,indent=2)+'\n')
