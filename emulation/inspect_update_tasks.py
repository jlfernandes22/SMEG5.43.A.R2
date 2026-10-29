#!/usr/bin/env python3
"""Read-only task/stack inspection of the isolated vendor updater; always resume."""
import argparse
import bisect
import gzip
import json
from pathlib import Path
import re
import struct
from elftools.elf.elffile import ELFFile
from debug_kernel import load_symbols
from run_usb_probe import QMP, RSP

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--directory',type=Path,required=True)
p.add_argument('--plugin-base',type=lambda x:int(x,0),required=True)
p.add_argument('--output',type=Path,required=True)
p.add_argument('--name-pattern', default='upg|upgrade|compat|trusted|BootRom|pthr',
               help='Regular expression selecting native task names')
a=p.parse_args()
syms=[]
for x in load_symbols(Path('artifacts/phase2/package/SMEG_PLUS_UPG/BSP/SMEG_PLUS_512/vxWorks.bin').read_bytes()):
 if x['kind']==0x500:syms.append((x['address'],x['name']))
for line in gzip.open('artifacts/phase3/payloads/SYSTEM/Application/PKG/abs_symbols_base.txt.gz','rt'):
 t=line.split()
 if len(t)>2:syms.append((int(t[0],16),t[2]))
with open('artifacts/phase2/package/SMEG_PLUS_UPG/UpgPlugin.out','rb')as f:
 e=ELFFile(f)
 for x in e.get_section_by_name('.symtab').iter_symbols():
  if x['st_info']['type']=='STT_FUNC' and x['st_shndx']==1:syms.append((a.plugin_base+x['st_value'],x.name))
syms.sort();addresses=[x[0]for x in syms]
def symbol(pc):
 i=bisect.bisect_right(addresses,pc)-1
 return syms[i][1]+'+'+hex(pc-syms[i][0]) if i>=0 else '?'
q=QMP(a.directory/'control.qmp');r=None
result={'scope':'Read-only stopped guest memory; original firmware; no injected calls','tasks':[]}
try:
 q.call('stop');r=RSP(a.directory/'control.gdb');r.req('qSupported');r.req('?');r.req('Qqemu.PhyMemMode:1')
 def mem(addr,size):
  b=r.req(f'm{addr:x},{size:x}')
  if b.startswith('E'):raise ValueError(b)
  return bytes.fromhex(b)
 def word(addr):return int.from_bytes(mem(addr,4),'big')
 cls=word(0x866fec);seen=set();result['task_class']=hex(cls);result['observed_names']=[]
 for off in [0x40,0x48]:
  node=word(cls+off)
  while node and node not in seen and len(seen)<512:
   seen.add(node);tcb=node-0x1c;raw=mem(tcb,0x290)
   def v(off):return int.from_bytes(raw[off:off+4],'big')
   name=mem(v(0x2c),64).split(b'\0',1)[0].decode(errors='replace') if v(0x2c) else ''
   result['observed_names'].append(name)
   if re.search(a.name_pattern,name,re.I):
    task={'name':name,'tcb':hex(tcb),'priority':v(0x74),'status':hex(v(0x70)),'saved_pc':hex(v(0x26c)),'saved_pc_symbol':symbol(v(0x26c)),'frames':[]}
    sp=v(0x1e4);base,end=v(0xc4),v(0xc8)
    for _ in range(24):
     if not end<=sp<base:break
     prev,lr=struct.unpack('>II',mem(sp,8));task['frames'].append({'sp':hex(sp),'lr':hex(lr),'symbol':symbol(lr)})
     if prev<=sp or prev>base:break
     sp=prev
    result['tasks'].append(task)
   node=word(node)
finally:
 if r:
  try:r.req('D')
  finally:r.s.close()
 q.call('cont');q.close();result['guest_resumed']=True
 a.output.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
