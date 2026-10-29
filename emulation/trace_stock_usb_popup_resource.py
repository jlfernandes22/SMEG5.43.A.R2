#!/usr/bin/env python3
"""Bounded read-only native popup/resource trace for private STOCKCOLDV753."""
import argparse,json,select,socket,time
from pathlib import Path
from run_usb_probe import ROOT,QMP,RSP
POINTS={0x289d748:'H_UPG_ActivatePopup_call',0x27364d8:'PopupState_Activate_entry',0x273670c:'Desktop_RequestPopUp_return',0x26044a0:'DesktopClient_RequestPopUp_entry',0x21ce898:'GetBinXmlWindow_entry',0x21cea60:'GetBinXmlWindow_return'}
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--seconds',type=int,default=180);a=p.parse_args();assert 1<=a.seconds<=300
 prefix='/tmp/smeg-p8-STOCKCOLDV753';out=ROOT/'artifacts/phase15/stock-cold-v7-acceptance/native-popup-resource-trace.json';assert not out.exists()
 original=(ROOT/'artifacts/phase2/applications/AUDIO_BT_256/app.bin').read_bytes();report={'guest_memory_writes':False,'guest_register_writes':False,'hardware_breakpoints_only':True,'events':[]};q=r=None;installed=set();stopped=False;start=time.monotonic();popup_seen=None
 def save():out.write_text(json.dumps(report,indent=2)+'\n')
 try:
  q=QMP(prefix+'.qmp');q.call('stop');stopped=True;r=RSP(prefix+'.gdb');r.s.settimeout(.5);r.req('qSupported');r.req('?');r.req('Qqemu.PhyMemMode:1')
  def mem(addr,n):
   assert 0x1000<=addr and addr+n<=0x10000000
   value=r.req(f'm{addr:x},{n:x}');assert not value.startswith('E');return bytes.fromhex(value)
  def word(addr):return int.from_bytes(mem(addr,4),'big')
  for pc in POINTS:
   assert mem(pc,16)==original[pc-0x1000000:pc-0x1000000+16],hex(pc)
   assert r.req(f'Z1,{pc:x},4')=='OK';installed.add(pc)
  q.close();q=None;report['armed']=True;save();r.send('c');stopped=False
  while time.monotonic()-start<a.seconds and len(report['events'])<200:
   if popup_seen and time.monotonic()-popup_seen>20:break
   if not select.select([r.s],[],[],.2)[0]:continue
   try:reply=r.recv()
   except socket.timeout:continue
   stopped=True;pc=r.reg(64);assert pc in installed,(reply,hex(pc));event={'name':POINTS[pc],'pc':hex(pc),'seconds':round(time.monotonic()-start,3),'registers':{str(i):hex(r.reg(i))for i in [3,4,5,31]}}
   if pc==0x27364d8:event.update(state=hex(r.reg(3)),popup_id=word(r.reg(3)+4))
   elif pc==0x273670c:
    state=word(r.reg(31)+0x38);event.update(state=hex(state),popup_id=word(state+4),returned_r3=hex(r.reg(3)),active_before_store=word(state+0x28))
    if event['popup_id']==9003:popup_seen=time.monotonic()
   elif pc==0x26044a0:event.update(popup_id=int.from_bytes(mem(r.reg(4),2),'big'),client_proxy=hex(word(r.reg(3)+12)))
   elif pc==0x21ce898:event.update(resource_app=r.reg(4),resource_window=r.reg(5))
   elif pc==0x21cea60:
    event.update(resource_app=word(r.reg(31)+0x2c),resource_window=word(r.reg(31)+0x30),returned_pointer=hex(r.reg(3)))
    if r.reg(3):event['resource_first16']=mem(r.reg(3),16).hex()
   report['events'].append(event);save();r.req(f'z1,{pc:x},4');r.req('s');r.req(f'Z1,{pc:x},4');r.send('c');stopped=False
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
  try:
   q.call('cont');report['guest_resumed']=q.call('query-status')['running'];q.call('screendump',{'filename':str(out.with_suffix('.png').resolve()),'format':'png'})
  finally:q.close()
  report['elapsed_seconds']=round(time.monotonic()-start,3);save();print(json.dumps(report))
if __name__=='__main__':main()
