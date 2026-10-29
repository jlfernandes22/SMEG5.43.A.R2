#!/usr/bin/env python3
"""Read-only native boot-popup trace through QEMU breakpoints; resumes on exit."""
import argparse,json,socket,time,struct,gzip,bisect
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,default=Path('artifacts/phase4/runs/hci_probe'));p.add_argument('--output',type=Path,default=Path('artifacts/phase4/hci-complete-trace.json'));p.add_argument('--seconds',type=int,default=40);a=p.parse_args()
report={'scope':'Emulator only, no firmware patches','events':[]};qs=socket.socket(socket.AF_UNIX);qs.settimeout(5);qs.connect(str(a.directory/'control.qmp'));qf=qs.makefile('rb');qf.readline();qid=0
def qmp(name,args=None):
 global qid
 qid+=1;m={'execute':name,'id':qid}
 if args is not None:m['arguments']=args
 qs.sendall((json.dumps(m)+'\n').encode())
 while True:
  r=json.loads(qf.readline())
  if r.get('id')==qid:
   if 'error'in r:raise RuntimeError(r['error'])
   return r.get('return')
qmp('qmp_capabilities');s=socket.socket(socket.AF_UNIX);s.settimeout(12);s.connect(str(a.directory/'control.gdb'))
def recv():
 while s.recv(1)!=b'$':pass
 b=bytearray()
 while True:
  c=s.recv(1)
  if c==b'#':break
  if not c:raise RuntimeError('GDB closed')
  b.extend(c)
 s.recv(2);s.sendall(b'+');return b.decode()
def send(c):
 b=c.encode();s.sendall(b'$'+b+b'#'+f'{sum(b)%256:02x}'.encode())
def req(c):send(c);return recv()
def reg(n):return int(req(f'p{n:x}'),16)
def mem(addr,n):return bytes.fromhex(req(f'm{addr:x},{n:x}'))
syms=[]
for l in gzip.open('artifacts/phase3/payloads/SYSTEM/Application/PKG/abs_symbols_base.txt.gz','rt'):
 t=l.split()
 if len(t)>2:syms.append((int(t[0],16),t[2]))
syms.sort();addresses=[x[0]for x in syms]
def name(pc):
 i=bisect.bisect_right(addresses,pc)-1
 return syms[i][1]+'+'+hex(pc-syms[i][0]) if i>=0 else '?'
points={0x179f600:'HCI command-complete pending lookup'};installed=[];stopped=False
try:
 qmp('stop');stopped=True;req('qSupported');req('?');req('Qqemu.PhyMemMode:1')
 for pc in points:assert req(f'Z0,{pc:x},4')=='OK';installed.append(pc)
 deadline=time.monotonic()+a.seconds
 while time.monotonic()<deadline and len(report['events'])<30:
  send('c');stopped=False
  try:reply=recv();stopped=True
  except socket.timeout:
   s.sendall(b'\x03');recv();stopped=True
   if report['events']:break
   continue
  pc=reg(64);sp=reg(1);event={'pc':hex(pc),'point':points.get(pc),'r3':hex(reg(3)),'r4':hex(reg(4)),'lr':hex(reg(67)),'lr_symbol':name(reg(67)),'frames':[]}
  for _ in range(12):
   if not 0x1000<sp<0x1ffffff0:break
   raw=mem(sp,8);prev,lr=struct.unpack('>II',raw);event['frames'].append({'sp':hex(sp),'lr':hex(lr),'symbol':name(lr)})
   if prev<=sp or prev-sp>0x10000:break
   sp=prev
  event['pending_command']=hex(reg(3));event['event_bytes']=mem(reg(31),8).hex()
  if 0x1000000 < reg(3) < 0x1fff0000:event['pending_bytes']=mem(reg(3),16).hex()
  report['events'].append(event);print(json.dumps(event),flush=True)
  if pc not in points:break
  req(f'z0,{pc:x},4');req('s');req(f'Z0,{pc:x},4')
finally:
 try:
  if not stopped:s.sendall(b'\x03');recv()
  for pc in installed:req(f'z0,{pc:x},4')
  req('D');qmp('cont');report['final_status']=qmp('query-status')
 finally:
  a.output.write_text(json.dumps(report,indent=2)+'\n');s.close();qs.close()
