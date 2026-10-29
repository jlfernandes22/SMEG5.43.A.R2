#!/usr/bin/env python3
"""Read-only RSP capture of original guest SQLite corruption branch.
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
print('BREAK',req('Z0,10afbe4,4'),flush=True)
stop=req('?')
if reg(64)!=0x10afbe4:stop=req('c')
print('STOP',stop,flush=True)
r={str(i):hex(reg(i)) for i in list(range(32))+[64,65,66,67]}
Path(a.output+'.registers').write_text(json.dumps(r,indent=2)); print('PC',r['64'],'SP',r['1'],flush=True)
print('PHYSMEM',req('Qqemu.PhyMemMode:1'),flush=True)
sp=int(r['1'],16);bt=int(r['22'],16);trunk=word(sp+12);data=word(trunk+0x40)
result={'stop':stop,'registers':r,'btree':hex(bt),'usable_size':word(bt+0x28),'trunk':hex(trunk),'trunk_data':hex(data),'trunk_first64':mem(data,64).hex(),'leaf_count_reg29':reg(29),'leaf_count_memory':word(data+4),'native_page_bytes':mem(data,1024).hex()}
Path(a.output).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k not in ['native_page_bytes','registers']}),flush=True)
req('z0,10afbe4,4');req('D');s.close()
