#!/usr/bin/env python3
"""Bind host GL routing to a fingerprint-verified native256 updater .text.

Does not change guest RAM or call guest functions. The only configuration write
is a paused QOM property belonging to QEMU's existing host GL API bridge.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import time
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from run_usb_probe import QMP,RSP

ROOT=Path(__file__).resolve().parents[1]


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--prefix',required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--seconds',type=int,default=1800)
    p.add_argument('--watch',action='store_true',help='Keep observing native module relocation across updater restarts')
    a=p.parse_args()
    assert 1<=a.seconds<=10800
    assert a.prefix.startswith('/tmp/smeg-p8-') and any(
        a.output.resolve().is_relative_to(ROOT/'artifacts'/phase)
        for phase in ('phase13', 'phase14', 'phase15'))
    source=ROOT/'artifacts/phase2/package/SMEG_PLUS_UPG/upgrade_256.out'
    with source.open('rb')as f:
        elf=ELFFile(f);sym=next(s for s in elf.get_section_by_name('.symtab').iter_symbols()if s.name=='_ZN9C_UPGRADE24StaticUpgradeDisplayTaskEPS_')
        entry=sym['st_value'];expected=elf.get_section(sym['st_shndx']).data()[entry:entry+64];mask=bytearray(b'\xff'*64)
        for section in elf.iter_sections():
            if isinstance(section,RelocationSection)and section['sh_info']==sym['st_shndx']:
                for relocation in section.iter_relocations():
                    off=relocation['r_offset']
                    if entry<=off<entry+64:
                        k=(off-entry)&~3;mask[k:k+4]=b'\0'*4
    assert entry==0x9540 and sum(bool(x)for x in mask)>=16
    deadline=time.monotonic()+a.seconds;report={'physical_device_access':False,'guest_RAM_writes':False,'guest_function_calls_injected':False,'USB_package_modified':False,'bindings':[]}
    while time.monotonic()<deadline:
        q=r=None;found=False
        try:
            q=QMP(a.prefix+'.qmp');q.call('stop');r=RSP(a.prefix+'.gdb');r.req('qSupported');r.req('?');r.req('Qqemu.PhyMemMode:1')
            def mem(addr,n):
                value=r.req(f'm{addr:x},{n:x}');assert not value.startswith('E');return bytes.fromhex(value)
            def word(addr):return int.from_bytes(mem(addr,4),'big')
            cls=word(0x866f9c);seen=set();task=None
            for off in [0x40,0x48]:
                node=word(cls+off)
                while node and node not in seen and len(seen)<512:
                    seen.add(node);tcb=node-0x1c;nameptr=word(tcb+0x2c)
                    name=mem(nameptr,32).split(b'\0')[0]if nameptr else b''
                    if name==b'tUpgDisp':task=tcb;break
                    node=word(node)
                if task:break
            if task:
                sp=word(task+0x1e4);end=word(task+0xc8);top=word(task+0xc4);last=None
                for _ in range(32):
                    if not end<=sp<top:break
                    prev,lr=struct.unpack('>II',mem(sp,8))
                    if lr==0x2acdac and last:
                        base=last-0x9588
                        if 0x1000000<=base<0x1f000000 and base%4096==0:
                            actual=mem(base+entry,64)
                            if all((x&m)==(y&m)for x,y,m in zip(actual,expected,mask)):
                                current=q.call('qom-get',{'path':'/machine','property':'updater-gl-base'})
                                if current!=base:
                                    q.call('qom-set',{'path':'/machine','property':'updater-gl-base','value':base})
                                    report['bindings'].append({'native_text_base':hex(base),'time_unix':time.time(),'previous_host_base':hex(current)})
                                assert q.call('qom-get',{'path':'/machine','property':'updater-gl-base'})==base
                                report.update(host_renderer_bound=True,native_text_base=hex(base),native_wrapper_fingerprint_verified=True,
                                    source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),bridge_type='Existing Mesa API renderer;173 exports at original offsets+0x74')
                                found=True
                        break
                    if not sp<prev<=top:break
                    last=lr;sp=prev
        except (OSError,EOFError,RuntimeError,AssertionError)as error:
            report['last_observation_error']=repr(error)
        finally:
            if r:
                try:r.req('D')
                finally:r.s.close()
            if q:
                try:q.call('cont')
                finally:q.close()
        if found:
            a.output.write_text(json.dumps(report,indent=2)+'\n')
            if not a.watch:
                print(json.dumps(report),flush=True);return
        if report.get('host_renderer_bound') and not Path(a.prefix+'.qmp').exists():
            report['VM_connection_ended']=True;a.output.write_text(json.dumps(report,indent=2)+'\n');return
        time.sleep(5)
    if report.get('host_renderer_bound'):
        report['bounded_watch_complete']=True;a.output.write_text(json.dumps(report,indent=2)+'\n');return
    report['host_renderer_bound']=False;a.output.write_text(json.dumps(report,indent=2)+'\n');raise SystemExit('No fingerprint-verified native display task before deadline')


if __name__=='__main__':main()
