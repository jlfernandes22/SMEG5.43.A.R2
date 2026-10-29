#!/usr/bin/env python3
"""Read-only RSP capture of original guest Qt GL context result.
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
print('BREAK',req('Z0,1df6e00,4'),flush=True)
stop=req('c');print('STOP',stop,flush=True)
r={str(i):hex(reg(i)) for i in list(range(32))+[64,65,66,67]}
print('PHYSMEM',req('Qqemu.PhyMemMode:1'),flush=True)
qt=reg(31)
result={'stop':stop,'registers':r,'qt_context':hex(qt),'cached_max_texture_size':hex(word(qt+0xf8)),'OGL_TLS_mode':hex(word(0x36d2a24)),'OGL_singleton_context':hex(word(0x36d29b0)),'OGL_task_table_first128':mem(0x36d29ac,128).hex()}
Path(a.output).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
req('z0,1df6e00,4');req('D');s.close()
