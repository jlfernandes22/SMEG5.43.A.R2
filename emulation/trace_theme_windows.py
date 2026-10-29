#!/usr/bin/env python3
"""Bounded hardware-breakpoint resource observation in a private P20 VM."""
import argparse,json,select,socket,time
from pathlib import Path
from run_usb_probe import QMP,RSP,ROOT

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--prefix',required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--seconds',type=int,default=55);p.add_argument('--cold',action='store_true',help='Arm before the app is loaded; validate instructions at each actual hit');a=p.parse_args()
 assert a.prefix.startswith('/tmp/smeg-p15-P20') and 1<=a.seconds<=120
 out=a.output.resolve();assert out.is_relative_to(ROOT/'artifacts/phase20') and not out.exists()
 points={0x21ce898:'getBinXmlWindow',0x20555f0:'createWindow',0x203f414:'ParseApplicationFile'}
 original=(ROOT/'artifacts/phase2/applications/AUDIO_BT_256/app.bin').read_bytes()
 q=QMP(a.prefix+'.qmp');q.call('stop');r=RSP(Path(a.prefix+'.gdb'));stopped=True;installed=[]
 report=dict(guest_memory_writes=False,hardware_breakpoints_only=True,events=[])
 try:
  r.req('qSupported');r.req('?');r.req('Qqemu.PhyMemMode:1')
  for pc in points:
   if not a.cold:assert bytes.fromhex(r.req(f'm{pc:x},10'))==original[pc-0x1000000:pc-0x1000000+16]
   assert r.req(f'Z1,{pc:x},4')=='OK';installed.append(pc)
  # Queue genuine native front-panel MENU and Radio interactions.
  variant=q.call('qom-get',{'path':'/machine','property':'frontpanel-key-variant'});key=1 if variant==0xa1 else 0
  if not a.cold:q.call('qom-set',{'path':'/machine','property':'frontpanel-event','value':key*256+1})
  q.close();q=None;r.send('c');stopped=False;start=time.monotonic();release=False;touched=False;up=False
  while time.monotonic()-start<a.seconds and len(report['events'])<300:
   elapsed=time.monotonic()-start
   if not a.cold and ((elapsed>1 and not release)or(elapsed>5 and not touched)or(elapsed>6 and not up)):
    q=QMP(a.prefix+'.qmp')
    if not release:q.call('qom-set',{'path':'/machine','property':'frontpanel-event','value':key*256+2});release=True
    elif not touched:
     q.call('input-send-event',{'events':[{'type':'abs','data':{'axis':'x','value':round(100*32767/799)}},{'type':'abs','data':{'axis':'y','value':round(215*32767/479)}},{'type':'btn','data':{'button':'left','down':True}}]});touched=True
    else:q.call('input-send-event',{'events':[{'type':'btn','data':{'button':'left','down':False}}]});up=True
    q.close();q=None
   if not select.select([r.s],[],[],.1)[0]:continue
   try:reply=r.recv()
   except socket.timeout:continue
   stopped=True;pc=r.reg(64);assert pc in points,reply
   assert bytes.fromhex(r.req(f'm{pc:x},10'))==original[pc-0x1000000:pc-0x1000000+16]
   event=dict(seconds=round(elapsed,2),function=points[pc],app=r.reg(4),window=r.reg(5));report['events'].append(event)
   r.req(f'z1,{pc:x},4');r.req('s');r.req(f'Z1,{pc:x},4');r.send('c');stopped=False
 finally:
  if q:q.close()
  if not stopped:
   q=QMP(a.prefix+'.qmp');q.call('stop');q.close();r.req('?')
  for pc in installed:r.req(f'z1,{pc:x},4')
  r.req('D');r.s.close();q=QMP(a.prefix+'.qmp');q.call('cont');q.close()
  out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))

if __name__=='__main__':main()
