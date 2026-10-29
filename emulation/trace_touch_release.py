#!/usr/bin/env python3
"""Trace original TS/QWS/widget events on an explicitly selected isolated VM."""
import argparse,json,socket,struct,threading,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--qmp',required=True);p.add_argument('--gdb',required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--x',type=int,default=30);p.add_argument('--y',type=int,default=230);p.add_argument('--hold-ms',type=float,default=250);a=p.parse_args()
POINTS={0x157ed4c:'TS DeBounceEnd arm',0x157f7e0:'TS DeBounceEnd expiry after flags cleared',0x15840d4:'TS Device Write',0x1abf6b8:'QWSMouseHandler mouseChanged',0x1ab89e8:'QWSServer sendMouseEvent',0x20bba74:'GUI Button mouseRelease',0x20bbac4:'GUI Button mousePress',0x20bbc4c:'GUI Button sendClick',0x213a8f8:'GUI Button clickedID',0x20d7bec:'GUI Label mousePress',0x20d7c10:'GUI Label mouseRelease'}
report={'scope':'Isolated headless VM only; original guest instructions unchanged; breakpoint instrumentation is not a latency measurement','qmp':a.qmp,'gdb':a.gdb,'events':[],'input':[]}; lock=threading.Lock();input_done=threading.Event();down=False
qs=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);qs.settimeout(5);qs.connect(a.qmp);qf=qs.makefile('rb');qf.readline();qid=0
def qmp(name,args=None):
 global qid
 with lock:
  qid+=1;message={'execute':name,'id':qid}
  if args is not None:message['arguments']=args
  qs.sendall((json.dumps(message)+'\n').encode())
  while True:
   r=json.loads(qf.readline())
   if r.get('id')==qid:
    if 'error'in r:raise RuntimeError(r['error'])
    return r.get('return')
qmp('qmp_capabilities')
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(5);s.connect(a.gdb)
def receive():
 while True:
  c=s.recv(1)
  if not c:raise RuntimeError('RSP closed')
  if c==b'$':break
 data=bytearray()
 while True:
  c=s.recv(1)
  if c==b'#':break
  if not c:raise RuntimeError('RSP closed')
  data.extend(c)
 s.recv(2);s.sendall(b'+');return data.decode()
def send(cmd):
 raw=cmd.encode();s.sendall(b'$'+raw+b'#'+f'{sum(raw)%256:02x}'.encode())
def req(cmd):send(cmd);return receive()
def reg(n):return int(req(f'p{n:x}'),16)
def mem(addr,n):
 r=req(f'm{addr:x},{n:x}')
 if r.startswith('E'):raise RuntimeError(r)
 return bytes.fromhex(r)
def point(addr):
 raw=mem(addr,16);x,y,z=struct.unpack('>fff',raw[:12]);return{'pointer':hex(addr),'x':x,'y':y,'pressure':z,'flags':raw[12],'timestamp':int.from_bytes(raw[14:16],'big')}
def save():a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n')
def inputs():
 global down
 try:
  time.sleep(.25)
  events=[{'type':'abs','data':{'axis':'x','value':round(a.x*32767/799)}},{'type':'abs','data':{'axis':'y','value':round(a.y*32767/479)}},{'type':'btn','data':{'button':'left','down':True}}]
  t=time.monotonic_ns();qmp('input-send-event',{'events':events});down=True;report['input'].append({'action':'down','monotonic_ns':t,'x':a.x,'y':a.y})
  time.sleep(a.hold_ms/1000)
  t=time.monotonic_ns();qmp('input-send-event',{'events':[{'type':'btn','data':{'button':'left','down':False}}]});down=False;report['input'].append({'action':'up','monotonic_ns':t})
 except Exception as e:report['input_error']=str(e)
 finally:input_done.set()
installed=[];stopped=False;thread=None
try:
 qmp('stop');stopped=True;report['qSupported']=req('qSupported');report['initial_stop']=req('?');req('Qqemu.PhyMemMode:1')
 for pc in POINTS:
  assert req(f'Z0,{pc:x},4')=='OK';installed.append(pc)
 thread=threading.Thread(target=inputs,daemon=True);thread.start();deadline=time.monotonic()+15
 while time.monotonic()<deadline and len(report['events'])<100:
  send('c');stopped=False
  try:stop=receive();stopped=True
  except socket.timeout:
   s.sendall(b'\x03');report['timeout_stop']=receive();stopped=True;break
  pc=reg(64);r={i:reg(i)for i in [3,4,5,6,30]};event={'pc':hex(pc),'name':POINTS.get(pc),'monotonic_ns':time.monotonic_ns(),'r3_r6':[hex(r[i])for i in range(3,7)]}
  if pc not in POINTS:report['unexpected_stop']=stop;break
  try:
   if pc in [0x157ed4c,0x15840d4]:event['point']=point(r[4])
   if pc==0x157f7e0:event['point']=point(r[30])
   if pc==0x1ab89e8:event.update(qpoint=struct.unpack('>ii',mem(r[3],8)),buttons=r[4],wheel=r[5])
   if pc==0x1abf6b8:event.update(qpoint=struct.unpack('>ii',mem(r[4],8)),buttons=r[5],wheel=r[6])
   event['runtime_instruction']=mem(pc,4).hex()
  except Exception as e:event['read_error']=str(e)
  report['events'].append(event);save();print(json.dumps(event),flush=True)
  req(f'z0,{pc:x},4');req('s');req(f'Z0,{pc:x},4')
except Exception as e:report['error']=str(e)
finally:
 try:
  if not stopped:s.sendall(b'\x03');report['cleanup_stop']=receive();stopped=True
  for pc in installed:req(f'z0,{pc:x},4')
  req('D');report['debugger_cleanup']='all breakpoints removed; detached/resumed'
 except Exception as e:report['cleanup_error']=str(e)
 if thread:thread.join(2)
 if down:
  try:qmp('input-send-event',{'events':[{'type':'btn','data':{'button':'left','down':False}}]});report['cleanup_mouse_up']=True
  except Exception as e:report['cleanup_input_error']=str(e)
 try:
  qmp('cont');report['final_status']=qmp('query-status')
 except Exception as e:report['final_resume_error']=str(e)
 save();s.close();qf.close();qs.close()
