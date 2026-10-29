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
points={0x2018ec4:'PVRSRVConnect return',0x2018f08:'PVRSRVEnumerateDevices return',0x2018f60:'PVRSRVAcquireDeviceData return',0x2018f84:'PVRSRVGetMBXInfo return',0x2018fc8:'PVRSRVGetMiscInfo return',0x20144a0:'SRV_ServicesInit return',0x20144d4:'WS initialize return',0x1df6e00:'Qt maxTextureSize query return'}
for pc in points:print('BREAK',hex(pc),req(f'Z0,{pc:x},4'),flush=True)
req('Qqemu.PhyMemMode:1')
events=[]
for _ in range(40):
 stop=req('c');pc=reg(64)
 event={'stop':stop,'pc':hex(pc),'name':points.get(pc),'result_r3':hex(reg(3)),'sp':hex(reg(1)),'lr':hex(reg(67)),'ogl_tls_mode':hex(word(0x36d2a24)),'ogl_context':hex(word(0x36d29b0))}
 if pc==0x1df6e00:event['qt_cached_texture_limit']=hex(word(reg(31)+0xf8))
 events.append(event);print(json.dumps(event),flush=True)
 Path(a.output).write_text(json.dumps(events,indent=2)+'\n')
 if pc==0x1df6e00:break
 # Remove, step original instruction, reinsert breakpoint before continuing.
 req(f'z0,{pc:x},4');req('s');req(f'Z0,{pc:x},4')
for pc in points:req(f'z0,{pc:x},4')
req('D');s.close()
