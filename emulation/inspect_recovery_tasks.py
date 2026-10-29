#!/usr/bin/env python3
"""Passive native BSP256 recovery task/stack snapshot; always resume QEMU."""
import argparse
import bisect
import json
from pathlib import Path
import re
import struct
from debug_kernel import load_symbols
from run_usb_probe import QMP,RSP

ROOT=Path(__file__).resolve().parents[1]


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--prefix',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    assert a.prefix.startswith('/tmp/smeg-') and a.output.resolve().is_relative_to(ROOT/'artifacts')
    symbols=load_symbols((ROOT/'artifacts/phase2/package/SMEG_PLUS_UPG/BSP/SMEG_PLUS_256/vxWorks.bin').read_bytes())
    sy=sorted((x['address'],x['name'])for x in symbols);keys=[x[0]for x in sy]
    cls_addr=next(x['address']for x in symbols if x['name']=='taskClassId')
    def symbol(pc):
        i=bisect.bisect_right(keys,pc)-1
        return sy[i][1]+'+'+hex(pc-sy[i][0])if i>=0 else '?'
    q=QMP(a.prefix+'.qmp');r=None
    result={'physical_device_access':False,'debugger_memory_writes':False,'native_function_calls_injected':False,'tasks':[],'names':[]}
    try:
        q.call('stop');r=RSP(a.prefix+'.gdb');r.req('qSupported');r.req('?');r.req('Qqemu.PhyMemMode:1')
        def mem(addr,n):
            raw=r.req(f'm{addr:x},{n:x}');assert not raw.startswith('E');return bytes.fromhex(raw)
        def word(addr):return int.from_bytes(mem(addr,4),'big')
        cls=word(cls_addr);seen=set()
        for off in [0x40,0x48]:
            node=word(cls+off)
            while node and node not in seen and len(seen)<512:
                seen.add(node);tcb=node-0x1c;raw=mem(tcb,0x290)
                def v(off):return int.from_bytes(raw[off:off+4],'big')
                name=mem(v(0x2c),64).split(b'\0')[0].decode(errors='replace')if v(0x2c) else ''
                result['names'].append(name)
                if re.search('Root|BootRom|FFX|[Uu][Pp][Gg]|[Uu]pgrade|[Ff]lash|[Cc]ompat|[Tt]rust',name):
                    task={'name':name,'tcb':hex(tcb),'status':hex(v(0x70)),'priority':v(0x74),'saved_pc':hex(v(0x26c)),'saved_pc_symbol':symbol(v(0x26c)),'frames':[]};sp=v(0x1e4)
                    for _ in range(25):
                        if not v(0xc8)<=sp<v(0xc4):break
                        prev,lr=struct.unpack('>II',mem(sp,8));frame={'sp':hex(sp),'lr':hex(lr),'symbol':symbol(lr)}
                        if lr==0x625610:
                            remaining=word(sp-4)
                            frame['elf_relocation_countdown']=remaining
                            frame['text_relocation_total']=32423
                        if 0x2c9000<=lr<0x2c9600:
                            saved=word(sp+0xc);frame['saved_r31_word']=hex(saved)
                            if 0x3000000<=saved<0x1f000000:
                                stdio=mem(saved,0x4c)
                                flags,fd=struct.unpack_from('>Hh',stdio,0x18);capacity=struct.unpack_from('>I',stdio,0x20)[0]
                                if 0<=fd<256 and 0<capacity<=65536:
                                    frame['stdio_candidate']={'pointer':hex(saved),'flags':hex(flags),'fd':fd,'buffer_capacity':capacity,'underlying_offset':struct.unpack_from('>I',stdio,0x48)[0],'unread':struct.unpack_from('>i',stdio,0x10)[0]}
                        task['frames'].append(frame)
                        if not sp<prev<=v(0xc4):break
                        sp=prev
                    result['tasks'].append(task)
                node=word(node)
    finally:
        if r:
            try:r.req('D')
            finally:r.s.close()
        q.call('cont');q.close();result['guest_resumed']=True
        a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'report':str(a.output),'tasks':[{k:t[k]for k in ['name','status','saved_pc','saved_pc_symbol']}for t in result['tasks']]}))


if __name__=='__main__':main()
