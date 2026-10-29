#!/usr/bin/env python3
"""Read-only RSP capture of original guest VxWorks MMI task context.
Launch QEMU with -S -gdb unix:SOCKET,server=on,wait=off on an isolated NAND.
Debugger breakpoints are QEMU runtime controls; no firmware bytes are changed.
"""
import argparse,json,socket,struct,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--socket',required=True);p.add_argument('--output',required=True);a=p.parse_args()
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(90);s.connect(a.socket)
def receive():
 while True:
  q=s.recv(1)
  if not q:raise RuntimeError('RSP closed')
  if q==b'$':break
 body=b''
 while True:
  q=s.recv(1)
  if q==b'#':break
  body+=q
 s.recv(2);s.sendall(b'+');return body.decode()
def req(q):
 raw=q.encode();s.sendall(b'$'+raw+b'#'+f'{sum(raw)%256:02x}'.encode());return receive()
def reg(n):return int(req(f'p{n:x}'),16)
def mem(addr,length):
 r=req(f'm{addr:x},{length:x}')
 if r.startswith('E'):raise RuntimeError(('read',hex(addr),r))
 return bytes.fromhex(r)
def word(addr):return struct.unpack('>I',mem(addr,4))[0]
print(req('qSupported'),req('?'),flush=True)
req('Qqemu.PhyMemMode:1')
cls=word(0x866fec);tasks=[];seen=set()
for listoff in [0x40,0x48]:
 node=word(cls+listoff)
 while node and node not in seen and len(tasks)<512:
  seen.add(node);tcb=node-0x1c
  raw=mem(tcb,0x290)
  def v(off):return struct.unpack_from('>I',raw,off)[0]
  np=v(0x2c)
  try:name=mem(np,64).split(b'\0')[0].decode(errors='replace') if np else ''
  except Exception:name='?'
  item={'tcb':hex(tcb),'name':name,'status':hex(v(0x70)),'priority':v(0x74),'pendQ':hex(v(0xa8)),'stack_base':hex(v(0xc4)),'stack_end':hex(v(0xc8)),'saved_sp':hex(v(0x1e4)),'saved_lr':hex(v(0x264)),'saved_pc':hex(v(0x26c))}
  if name=='MMI_id0':
   frames=[];sp=v(0x1e4);base=v(0xc4);end=v(0xc8)
   for _ in range(64):
    if not end<=sp<base:break
    frame=mem(sp,8);prev,lr=struct.unpack('>II',frame)
    frames.append({'sp':hex(sp),'backchain':hex(prev),'lr_at_sp4':hex(lr)})
    if prev<=sp or prev>base:break
    sp=prev
   item['frames']=frames
  tasks.append(item);node=word(node)
result={'task_class':hex(cls),'tasks':tasks};Path(a.output).write_text(json.dumps(result,indent=2)+'\n')
print('TASKS',len(tasks),flush=True)
for task in tasks:
 if task['name']=='MMI_id0':print(json.dumps({k:v for k,v in task.items() if k!='frames'}),flush=True)
req('D');s.close()
