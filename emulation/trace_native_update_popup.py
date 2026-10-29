#!/usr/bin/env python3
"""Observe stock AUDIO_BT_256 updater-dialog submission; no guest writes."""
import argparse,json,select,socket,time
from pathlib import Path
from run_usb_probe import QMP,RSP

ROOT=Path(__file__).resolve().parents[1]
POINTS={0x273670c:'RequestPopUp_return',0x26044a0:'client_RequestPopUp',
        0x150ab14:'service_RequestPopUp',0x150a3c8:'process_zone'}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--prefix',required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--seconds',type=int,default=240);a=p.parse_args()
    assert a.prefix.startswith('/tmp/smeg-') and 1<=a.seconds<=600
    assert a.output.resolve().is_relative_to(ROOT/'artifacts/phase13') and not a.output.exists()
    report={'guest_memory_writes':False,'guest_register_writes':False,'events':[]}
    app=(ROOT/'artifacts/phase2/applications/AUDIO_BT_256/app.bin').read_bytes()
    q=r=None;installed=set();stopped=False;start=time.monotonic();seen=None
    try:
        while not Path(a.prefix+'.qmp').exists():
            if time.monotonic()-start>30:raise TimeoutError('Private QMP unavailable')
            time.sleep(.1)
        q=QMP(a.prefix+'.qmp');q.call('stop');stopped=True
        r=RSP(a.prefix+'.gdb');r.s.settimeout(.5);r.req('qSupported');r.req('?');r.req('Qqemu.PhyMemMode:1')
        def mem(addr,n):
            assert 0x1000<=addr and addr+n<=0x20000000
            return bytes.fromhex(r.req(f'm{addr:x},{n:x}'))
        def word(addr):return int.from_bytes(mem(addr,4),'big')
        for pc in POINTS:
            assert r.req(f'Z1,{pc:x},4')=='OK';installed.add(pc)
        q.close();q=None
        report['status']='armed';a.output.write_text(json.dumps(report,indent=2)+'\n')
        r.send('c');stopped=False
        while time.monotonic()-start<a.seconds and len(report['events'])<150:
            if seen is not None and time.monotonic()-seen>2:break
            if not select.select([r.s],[],[],.2)[0]:continue
            try:reply=r.recv()
            except socket.timeout:continue
            stopped=True;pc=r.reg(64)
            assert pc in installed,(reply,hex(pc))
            assert mem(pc,16)==app[pc-0x1000000:pc-0x1000000+16], 'Stock app fingerprint mismatch'
            e={'name':POINTS[pc],'pc':hex(pc),'elapsed_seconds':round(time.monotonic()-start,3),
               'registers':{str(i):hex(r.reg(i))for i in range(3,11)}}
            if pc==0x273670c:
                state=word(r.reg(31)+0x38);e.update(state=hex(state),popup_id=word(state+4),returned_r3=hex(r.reg(3)),active_before_store=word(state+0x28))
                if e['popup_id']==9003:seen=time.monotonic()
            elif pc==0x26044a0:
                e.update(popup_id=int.from_bytes(mem(r.reg(4),2),'big'),client_connection=hex(word(r.reg(3)+12)))
            elif pc==0x150ab14:e['popup_id']=r.reg(4)
            elif pc==0x150a3c8:
                for i in (3,4):
                    if 0x1000<r.reg(i)<0x1fffff80:e['memory_r'+str(i)]=mem(r.reg(i),128).hex()
            report['events'].append(e)
            a.output.write_text(json.dumps(report,indent=2)+'\n')
            r.req(f'z1,{pc:x},4');r.req('s');r.req(f'Z1,{pc:x},4');r.send('c');stopped=False
    except Exception as e:report['error']=repr(e)
    finally:
        if q:q.close()
        if r:
            if not stopped:r.s.sendall(b'\x03');r.recv()
            for pc in installed:r.req(f'z1,{pc:x},4')
            r.req('D');r.s.close()
        q=QMP(a.prefix+'.qmp');q.call('cont');report['guest_resumed']=q.call('query-status')['running']
        if seen is not None:
            time.sleep(2)
            capture=a.output.with_suffix('.png').resolve()
            q.call('screendump',{'filename':str(capture),'format':'png'})
            report['confirmation_capture']=str(capture)
        q.close()
        report['elapsed_seconds']=round(time.monotonic()-start,3)
        a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))

if __name__=='__main__':main()
