#!/usr/bin/env python3
"""Bounded read-only native DOSFS pre-format checkpoints; no guest writes."""
import argparse
import hashlib
import json
from pathlib import Path
import select
import socket
import time
from run_usb_probe import QMP, RSP

ROOT = Path(__file__).resolve().parents[1]
POINTS = {0x467898:'entry',0x467914:'first_open_return',0x467928:'event_setup_return',
          0x467950:'ioctl_return',0x467984:'wait_path_return',0x46799c:'second_open_return',
          0x4679e4:'formatter_return'}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--prefix',required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--seconds',type=int,default=180);a=p.parse_args()
    assert a.prefix.startswith('/tmp/smeg-p8-') and 1<=a.seconds<=600
    assert a.output.resolve().is_relative_to(ROOT/'artifacts/phase13') and not a.output.exists()
    kernel=(ROOT/'artifacts/phase2/package/SMEG_PLUS_UPG/BSP/SMEG_PLUS_256/vxWorks.bin').read_bytes()
    assert hashlib.sha256(kernel).hexdigest()=='e8aff17981ae5ba8c1574fba70ed747d32ae08badec932bfae38b7f6a4694110'
    report={'guest_memory_or_register_writes':False,'events':[]};q=QMP(a.prefix+'.qmp');r=None;installed=[];stopped=True
    def save():a.output.write_text(json.dumps(report,indent=2)+'\n')
    try:
        q.call('stop');r=RSP(a.prefix+'.gdb');r.s.settimeout(1)
        r.req('qSupported');r.req('?');r.req('Qqemu.PhyMemMode:1')
        def word(addr):return int(r.req(f'm{addr:x},4'),16)
        assert bytes.fromhex(r.req('m200000,100'))==kernel[:256]
        for pc in POINTS:
            assert r.req(f'Z1,{pc:x},4')=='OK';installed.append(pc)
        q.close();q=None;r.send('c');stopped=False;deadline=time.monotonic()+a.seconds
        while time.monotonic()<deadline:
            if not select.select([r.s],[],[],.2)[0]:continue
            try:reply=r.recv()
            except socket.timeout:continue
            stopped=True;pc=r.reg(64)
            if pc not in POINTS:raise RuntimeError('Unexpected debug stop '+hex(pc))
            tcb=word(0x867bb8);event={'point':POINTS[pc],'pc':hex(pc),'r3':hex(r.reg(3)),
                'r4':hex(r.reg(4)),'r5':hex(r.reg(5)),'r31':hex(r.reg(31)),
                'task':r.string(word(tcb+0x2c)),'errno':hex(word(tcb+0xd0))}
            if POINTS[pc]=='entry':event['path']=r.string(r.reg(3))
            report['events'].append(event);save()
            # Execute the actual instruction once before rearming hardware BP.
            assert r.req(f'z1,{pc:x},4')=='OK';r.req('s');assert r.req(f'Z1,{pc:x},4')=='OK'
            r.send('c');stopped=False
    except Exception as error:report['error']=repr(error)
    finally:
        if r:
            if not stopped:r.s.sendall(b'\x03');r.recv()
            for pc in installed:r.req(f'z1,{pc:x},4')
            r.req('D');r.s.close()
        if q:q.close()
        q=QMP(a.prefix+'.qmp')
        try:q.call('cont')
        finally:q.close()
        report['guest_resumed']=True;save()
        print(json.dumps(report),flush=True)


if __name__=='__main__':main()
