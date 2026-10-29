#!/usr/bin/env python3
"""Observe original Internet UI/desktop calls in a disposable SMEG snapshot."""
import argparse
import json
import socket
import time
from pathlib import Path
from run_usb_probe import QMP, RSP

ROOT=Path(__file__).resolve().parents[1]
POINTS={0x4c8fd54:'openPanel',0x4c8fed4:'openPanel_result',
    0x2604e48:'desktop_ProcessCommand',0x2604ef8:'desktop_ProcessCommand_result',
    0x26077b0:'DBus_ProcessCommand',0x228500c:'desktop_ShowMenuItem',
    0x228b16c:'desktop_OnEventEnterMenu',0x22957bc:'desktop_HandleDBusMessage',
    0x4cc92b4:'secondary_SetScreenProperties',0x4cc8f2c:'secondary_GetMenuItemData',
    0x4cc9158:'secondary_widget_action',0x4c86c38:'isInternetProfileReady',
    0x4c86cec:'isFullWebAvailable',0x4c8fcc4:'openPopup',
    0x4ccf454:'activatePopup',0x4c8659c:'getWebBrowserButtonState',
    0x4c86668:'getWebBrowserButtonState_result'}
POINTS[0x2299f8c]='desktop_spy'
POINTS.update({0x4ca7504:'WWW_HandleSystemMessage',0x2708a40:'CreateNotificationCommand',
               0x228b498:'desktop_ShowMenuItemList'})


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--prefix',required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--current-screen',action='store_true',help='Start from an already verified Connect Apps screen')
    a=p.parse_args();out=a.output.resolve()
    assert out.is_relative_to(ROOT/'artifacts')
    out.mkdir(parents=True,exist_ok=False)
    q=QMP(a.prefix+'.qmp');q.call('stop')
    r=RSP(a.prefix+'.gdb');r.req('qSupported');r.req('?');r.req('Qqemu.PhyMemMode:1');r.s.settimeout(.04)
    report={'physical_device_access':False,'firmware_changed_by_tracer':False,'events':[],'screenshots':{}}
    installed=set();counts={};stopped=True;started=time.monotonic()
    def mem(addr,n):return bytes.fromhex(r.req(f'm{addr:x},{n:x}'))
    def save():(out/'trace.json').write_text(json.dumps(report,indent=2)+'\n')
    def pump(seconds):
        nonlocal stopped
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            try:r.recv();stopped=True
            except socket.timeout:continue
            pc=r.reg(64)
            if pc not in installed:raise RuntimeError('Unexpected debugger stop '+hex(pc))
            e={'name':POINTS[pc],'pc':hex(pc),'elapsed':round(time.monotonic()-started,3),
               'arguments':[hex(r.reg(n)) for n in (3,4,5,6)],'lr':hex(r.reg(67))}
            if pc==0x2604e48:
                e.update(item=int.from_bytes(mem(r.reg(4),2),'big'),
                         command=int.from_bytes(mem(r.reg(5),2),'big'),
                         argument=int.from_bytes(mem(r.reg(6),4),'big'))
                e['service_peer']=mem(r.reg(3)+0xc,4).hex()
            if pc==0x2604ef8:e['status']=int.from_bytes(mem(r.reg(31)+8,4),'big',signed=True)
            if pc==0x4c8fed4:e['success']=mem(r.reg(31)+0xc,1)[0]
            if pc==0x4c86668:
                f=r.reg(31);ptr=int.from_bytes(mem(f+0xc,4),'big');e['enabled']=mem(ptr,1)[0]
            if pc in (0x4c86c38,0x4c86cec,0x4c8659c):
                obj=r.reg(3);e['flags']=mem(obj+0x51390,9).hex()
                e['PPP_state']=int.from_bytes(mem(obj+0x50df8,4),'big')
            if pc==0x4cc9158:e['widget']=int.from_bytes(mem(r.reg(4),2),'big')
            if pc==0x2299f8c:e['text']=mem(r.reg(4),384).split(b'\0')[0].decode('latin1')
            if pc==0x2708a40:e['command_args']=[hex(r.reg(n)) for n in range(4,11)]
            if pc in (0x22957bc,0x228500c):
                try:e['message']=mem(r.reg(4),24).hex()
                except (ValueError,RuntimeError):pass
            report['events'].append(e);save()
            assert r.req(f'z0,{pc:x},4')=='OK';r.req('s');counts[pc]=counts.get(pc,0)+1
            if counts[pc]<40:assert r.req(f'Z0,{pc:x},4')=='OK'
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
        q.call('screendump',{'filename':str(out/(name+'.png')),'format':'png'})
        report['screenshots'][name]=str((out/(name+'.png')).relative_to(ROOT));save()
    try:
        for pc in POINTS:
            assert r.req(f'Z0,{pc:x},4')=='OK';installed.add(pc)
        r.send('c');stopped=False
        if not a.current_screen:
            q.call('qom-set',{'path':'/machine','property':'frontpanel-event','value':0x102})
            pump(6);shot('main-menu')
            tap(400,215);pump(6)
        shot('connect-apps')
        tap(35,230);pump(8);shot('secondary-attempt')
        tap(190,210);pump(5);shot('browser-attempt')
    except Exception as exc:report['error']=repr(exc)
    finally:
        try:
            if not stopped:r.s.sendall(b'\x03');r.recv();stopped=True
            for pc in installed:r.req(f'z0,{pc:x},4')
            r.req('D');r.s.close();q.call('cont')
            report['guest_resumed']=True
        finally:q.close();save()
    print(json.dumps({'trace':str(out/'trace.json'),'error':report.get('error'),'events':len(report['events'])}))


if __name__=='__main__':main()
