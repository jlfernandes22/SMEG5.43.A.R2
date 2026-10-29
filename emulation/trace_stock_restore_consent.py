#!/usr/bin/env python3
"""Read-only hardware-breakpoint observer for private STOCK25649 consent."""
import argparse,json,select,socket,time
from pathlib import Path
from run_usb_probe import ROOT,QMP,RSP
POINTS={0x28d0d5c:'Yes_event3000',0x28d0edc:'No_event3500',0x268a3b8:'native_Launch_entry',0x28d0e08:'native_Launch_return'}
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--seconds',type=int,default=180);a=p.parse_args();assert 1<=a.seconds<=300
 prefix='/tmp/smeg-p8-STOCK25649';out=ROOT/'artifacts/phase15/stock-restore256/native-consent-trace.json';assert not out.exists()
 original=(ROOT/'artifacts/phase2/applications/AUDIO_BT_256/app.bin').read_bytes();report={'guest_memory_writes':False,'guest_register_writes':False,'hardware_breakpoints_only':True,'events':[]};q=r=None;installed=set();stopped=False;start=time.monotonic()
 def save():out.write_text(json.dumps(report,indent=2)+'\n')
 try:
  q=QMP(prefix+'.qmp');q.call('stop');stopped=True;r=RSP(prefix+'.gdb');r.s.settimeout(.5);r.req('qSupported');r.req('?');r.req('Qqemu.PhyMemMode:1')
  def mem(addr,n):
   assert 0x1000<=addr and addr+n<=0x10000000
   value=r.req(f'm{addr:x},{n:x}');assert not value.startswith('E');return bytes.fromhex(value)
  for pc in POINTS:
   assert mem(pc,16)==original[pc-0x1000000:pc-0x1000000+16];assert r.req(f'Z1,{pc:x},4')=='OK';installed.add(pc)
  q.close();q=None;report['armed']=True;save();r.send('c');stopped=False
  while time.monotonic()-start<a.seconds and len(report['events'])<20:
   if not select.select([r.s],[],[],.2)[0]:continue
   try:reply=r.recv()
   except socket.timeout:continue
   stopped=True;pc=r.reg(64);assert pc in installed,(reply,hex(pc));event={'name':POINTS[pc],'pc':hex(pc),'seconds':round(time.monotonic()-start,3),'registers':{str(i):hex(r.reg(i))for i in [3,4,5,31]}}
   if pc==0x268a3b8:
    event['upgrade_type_pointer_bytes']=mem(r.reg(4),4).hex();event['info_vector_header']=mem(r.reg(5),12).hex()
   report['events'].append(event);save()
   r.req(f'z1,{pc:x},4');r.req('s');r.req(f'Z1,{pc:x},4')
   if pc==0x28d0e08:break
   r.send('c');stopped=False
 except Exception as e:report['error']=repr(e)
 finally:
  if q:q.close()
  if r:
   try:
    if not stopped:r.s.sendall(b'\x03');r.recv()
    for pc in installed:r.req(f'z1,{pc:x},4')
    r.req('D')
   finally:r.s.close()
  q=QMP(prefix+'.qmp')
  try:q.call('cont');report['guest_resumed']=q.call('query-status')['running']
  finally:q.close()
  report['elapsed_seconds']=round(time.monotonic()-start,3);save();print(json.dumps(report))
if __name__=='__main__':main()
