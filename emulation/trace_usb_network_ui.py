#!/usr/bin/env python3
"""Read-only debugger observation after a native USB network-cache experiment.

Only QEMU-local sockets and screenshots are used. No debugger memory writes,
guest function injection, physical device, Bluetooth radio or network traffic.
"""
import argparse
import json
import socket
import time
from pathlib import Path
from run_usb_probe import QMP, RSP

ROOT=Path(__file__).resolve().parents[1]
POINTS={0x227f7fc:'desktop_internet_availability',0x4c170c0:'backend_entry',
    0x4c17174:'backend_Web_active',0x4c171bc:'backend_INT_E_limit',
    0x4c171cc:'backend_return',0x27b2b10:'BT_cached_INT_E',
    0x182f544:'agenda_DUN_event',0x4c8fd54:'internet_openPanel',
    0x4c86c38:'isInternetProfileReady',0x4c86cec:'isFullWebAvailable'}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--prefix',required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--menu-seconds',type=int,default=25,help='Match the longer successful NAV control wait')
    a=p.parse_args();out=a.output.resolve()
    if not out.is_relative_to(ROOT/'artifacts'):p.error('Workspace artifacts required')
    out.mkdir(parents=True,exist_ok=False)
    q=QMP(a.prefix+'.qmp');q.call('stop')
    r=RSP(a.prefix+'.gdb');r.req('qSupported');r.req('?');r.req('Qqemu.PhyMemMode:1');r.s.settimeout(.03)
    report={'physical_device_access':False,'debugger_memory_writes':False,'events':[],'screenshots':{}}
    installed=set();counts={};pending={};stopped=True;started=time.monotonic()
    def mem(addr,n):
        raw=r.req(f'm{addr:x},{n:x}')
        if raw.startswith('E'):raise RuntimeError('Guest read failed '+hex(addr))
        return bytes.fromhex(raw)
    def save():(out/'trace.json').write_text(json.dumps(report,indent=2)+'\n')
    def pump(seconds):
        nonlocal stopped
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            try:r.recv();stopped=True
            except socket.timeout:continue
            pc=r.reg(64)
            if pc not in installed:raise RuntimeError('Unexpected debugger stop '+hex(pc))
            event={'name':POINTS[pc],'elapsed':round(time.monotonic()-started,3),'pc':hex(pc)}
            if pc==0x4c170c0:pending[r.reg(1)]=(r.reg(4),r.reg(5))
            elif pc==0x4c17174:event['Web_active']=mem(r.reg(30),1)[0]
            elif pc==0x4c171bc:event.update(INT_E_limit=r.reg(3),Web_and_BT_DUN=r.reg(28))
            elif pc==0x4c171cc:
                ptr=pending.pop(r.reg(1)+0x20,None)
                if ptr:event.update(web_available=mem(ptr[0],1)[0],portal_available=mem(ptr[1],1)[0])
            elif pc==0x227f7fc:
                frame=r.reg(31)
                event['inputs']={name:mem(frame+off,1)[0] for name,off in {
                    'SW_OPTION_INTERNET':0x44,'PSA_portal_active':0x45,'Web_active':0x46,
                    'BT_activated':0x4c,'SW_OPTION_BT_DUN':0x4d,'INT_E':0x4e}.items()}
                ptr=[int.from_bytes(mem(frame+off,4),'big')for off in (0x5c,0x60)]
                event.update(web_available=mem(ptr[0],1)[0],portal_available=mem(ptr[1],1)[0])
            elif pc==0x27b2b10:event['INT_E']=mem(r.reg(3)+0x51006,1)[0]
            elif pc==0x182f544:event['force_no_dun']=mem(r.reg(3)+0xba,1)[0]
            elif pc in (0x4c86c38,0x4c86cec):
                obj=r.reg(3);event['availability']=mem(obj+0x51390,9).hex()
                event['PPP_state']=int.from_bytes(mem(obj+0x50df8,4),'big')
            elif pc==0x4c8fd54:event['arguments']=[r.reg(n)for n in (4,5,6)]
            report['events'].append(event);save()
            assert r.req(f'z0,{pc:x},4')=='OK';r.req('s');counts[pc]=counts.get(pc,0)+1
            if counts[pc]<20:assert r.req(f'Z0,{pc:x},4')=='OK'
            else:installed.remove(pc)
            r.send('c');stopped=False
    def tap(x,y):
        q.call('input-send-event',{'events':[
            {'type':'abs','data':{'axis':'x','value':round(x*32767/799)}},
            {'type':'abs','data':{'axis':'y','value':round(y*32767/479)}},
            {'type':'btn','data':{'button':'left','down':True}}]})
        pump(.18)
        q.call('input-send-event',{'events':[{'type':'btn','data':{'button':'left','down':False}}]})
    def shot(name):
        path=out/(name+'.png');q.call('screendump',{'filename':str(path),'format':'png'})
        report['screenshots'][name]=str(path.relative_to(ROOT));save()
    def menu():
        variant=q.call('qom-get',{'path':'/machine','property':'frontpanel-key-variant'})
        q.call('qom-set',{'path':'/machine','property':'frontpanel-event','value':(0x100 if variant==0xa1 else 0)|2})
        pump(3)
    try:
        for pc in POINTS:assert r.req(f'Z0,{pc:x},4')=='OK';installed.add(pc)
        r.send('c');stopped=False
        pump(.5);menu();shot('main-menu');tap(400,215);pump(10);shot('connect-apps')
        tap(35,230);pump(a.menu_seconds);shot('internet-menu')
        original_variant=q.call('qom-get',{'path':'/machine','property':'frontpanel-key-variant'})
        report['secondary_key_fixture']={'original_variant':original_variant,'test_variant':0xa1,'key':0,'status':2,'saved_FMUX_modified':False}
        if original_variant!=0xa1:
            q.call('qom-set',{'path':'/machine','property':'frontpanel-key-variant','value':0xa1});pump(1)
        q.call('qom-set',{'path':'/machine','property':'frontpanel-event','value':2})
        pump(a.menu_seconds);shot('internet-hardware-menu')
        if original_variant!=0xa1:
            q.call('qom-set',{'path':'/machine','property':'frontpanel-key-variant','value':original_variant});pump(1)
        tap(190,210);pump(15);shot('browser-attempt')
        menu();tap(550,215);pump(6);shot('phone')
        tap(35,230);pump(6);shot('phone-menu')
        report['guest_status']=q.call('query-status')
    except Exception as exc:report['error']=repr(exc)
    finally:
        try:
            if not stopped:r.s.sendall(b'\x03');r.recv();stopped=True
            for pc in installed:r.req(f'z0,{pc:x},4')
            r.req('D');r.s.close();q.call('cont');report['guest_resumed']=True
        finally:q.close();save()
    print(json.dumps({'trace':str(out/'trace.json'),'error':report.get('error'),'events':len(report['events'])}))
    if report.get('error'):raise SystemExit(1)


if __name__=='__main__':main()
