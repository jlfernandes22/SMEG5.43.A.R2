#!/usr/bin/env python3
"""Trace original TS/QWS/widget events on an explicitly selected isolated VM."""
import argparse,json,socket,struct,threading,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--qmp',required=True);p.add_argument('--gdb',required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--x',type=int,default=30);p.add_argument('--y',type=int,default=230);p.add_argument('--hold-ms',type=float,default=250);a=p.parse_args()
POINTS={0x112f71c:'SSM StartUp original entry',0x112f764:'config GetValue return',0x112f798:'symFindByName return',0x112f7f8:'taskSpawn return or skipped',0x112f7f4:'before taskSpawn',0x112f850:'SSM Init entry',0x4c00000:'InitializeMetaPost original entry',0x4c00224:'InitializePkgWWW original entry',0x4c98b64:'HMI Internet Initialize original entry'}
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
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(60);s.connect(a.gdb)
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
installed=[];stopped=False
try:
 qmp('stop');stopped=True;req('qSupported');req('?');req('Qqemu.PhyMemMode:1')
 for pc in POINTS:
  assert req(f'Z0,{pc:x},4')=='OK';installed.append(pc)
 deadline=time.monotonic()+65
 while time.monotonic()<deadline and len(report['events'])<30:
  send('c');stopped=False
  try:stop=receive();stopped=True
  except socket.timeout:
   s.sendall(b'\x03');report['timeout_stop']=receive();stopped=True;break
  pc=reg(64);event={'pc':hex(pc),'name':POINTS.get(pc),'r3':hex(reg(3)),'r4':hex(reg(4)),'lr':hex(reg(67)),'sp':hex(reg(1))}
  event['registers']={str(n):hex(reg(n)) for n in [0,3,4,5,6,7,8,9,10,25,31]}
  if pc==0x112f798:
   ptr=int.from_bytes(mem(reg(1)+0x2c,4),'big');event['resolved_loader']=hex(ptr);base=ptr-0x14354
   for offset,name in [(0x14354,'Process_MetaPostponed entry'),(0x13e18,'load_MetaPostponed entry'),(0x13ed8,'ReadNand_area return'),(0x13f38,'inflate_n return'),(0x1442c,'load_MetaPostponed return'),(0x14468,'InitializeMetaPost return')]:
    pp=base+offset
    if pp not in POINTS:POINTS[pp]=name;assert req(f'Z0,{pp:x},4')=='OK';installed.append(pp)
  if POINTS.get(pc)=='ReadNand_area return':
   event['header64']=mem(reg(25),64).hex();event['read_buffer_head64']=mem(reg(31),64).hex()

  report['events'].append(event);save();print(event,flush=True)
  if pc not in POINTS:report['unexpected_stop']=stop;break
  if POINTS.get(pc)=='InitializeMetaPost return' or (POINTS.get(pc)=='load_MetaPostponed return' and reg(3)==0xffffffff):break
  req(f'z0,{pc:x},4');req('s');req(f'Z0,{pc:x},4')
finally:
 try:
  if not stopped:s.sendall(b'\x03');report['cleanup_stop']=receive();stopped=True
  for pc in installed:req(f'z0,{pc:x},4')
  req('D');report['debugger_cleanup']='all breakpoints removed; detached/resumed'
 except Exception as e:report['cleanup_error']=str(e)
 try:qmp('cont');report['final_status']=qmp('query-status')
 except Exception as e:report['resume_error']=str(e)
 save();s.close();qs.close()
