#!/usr/bin/env python3
"""Read clock globals and tick advancement through QMP; no guest calls or stops."""
import argparse,json,re,socket,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--socket',type=Path,default=Path('artifacts/phase3/interactive.qmp'));p.add_argument('--output',type=Path,default=Path('artifacts/phase3/native-clock-runtime.json'));p.add_argument('--seconds',type=float,default=1);a=p.parse_args()
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(10);s.connect(str(a.socket));f=s.makefile('rb');json.loads(f.readline());serial=0
def qmp(command,args=None):
 global serial
 serial+=1;m={'execute':command,'id':serial}
 if args is not None:m['arguments']=args
 s.sendall((json.dumps(m)+'\n').encode())
 while True:
  r=json.loads(f.readline())
  if r.get('id')==serial:
   if 'error'in r:raise RuntimeError(r['error'])
   return r.get('return')
def words(address,count):
 t=qmp('human-monitor-command',{'command-line':f'xp /{count}wx {address:#x}'})
 return [int(v,16) for l in t.splitlines() if ':'in l for v in re.findall(r'0x([0-9a-fA-F]+)',l.split(':',1)[1])]
qmp('qmp_capabilities');r={'method':'Read-only QMP/HMP physical RAM reads; no stop, guest call or patch','getter':'vxbSysClkRateGet0x002f143c','SDA_base':'0x0086dbb0','callback_address':'0x00865f2c','handle_address':'0x00865fc4'}
r['callback']=hex(words(0x865f2c,1)[0]);handle=words(0x865fc4,1)[0];r['handle']=hex(handle)
if handle:
 r['handle_words']=[hex(x) for x in words(handle,30)];r['handle_rate_hz']=words(handle+0x14,1)[0];r['driver_frequency_hz']=words(handle+4,1)[0];r['driver_reload']=words(handle+0x68,1)[0]
ctrl=words(0x36777dc,1)[0];r['touch_ctrl']=hex(ctrl)
if ctrl:
 r['touch_filter_words_7c_b4']=[hex(v) for v in words(ctrl+0x7c,15)];pair=words(ctrl+0xa8,1)[0];r['touch_a8']=pair>>16;r['touch_aa']=pair&65535;r['release_watchdog_ticks']=r['touch_aa']//2
samples=[]
for index in range(3):
 t0=time.monotonic_ns();tick=words(0x867c28,2);registers=qmp('human-monitor-command',{'command-line':'info registers'});t1=time.monotonic_ns();tb=re.search(r'\bTB\s+(\d+)\s+(\d+)\s+DECR',registers);samples.append({'monotonic_ns':(t0+t1)//2,'read_duration_ns':t1-t0,'timebase':int(tb.group(2)) if tb else None,'vxAbsTicks_words':tick,'vxAbsTicks':(tick[0]<<32)|tick[1]})
 if index<2:time.sleep(a.seconds)
r['samples']=samples;r['observed_tick_hz']=(samples[-1]['vxAbsTicks']-samples[0]['vxAbsTicks'])*1e9/(samples[-1]['monotonic_ns']-samples[0]['monotonic_ns'])
if all(x['timebase'] is not None for x in samples) and samples[-1]['vxAbsTicks']!=samples[0]['vxAbsTicks']:
 r['observed_tb_hz']=(samples[-1]['timebase']-samples[0]['timebase'])*1e9/(samples[-1]['monotonic_ns']-samples[0]['monotonic_ns']);r['timebase_counts_per_tick']=(samples[-1]['timebase']-samples[0]['timebase'])/(samples[-1]['vxAbsTicks']-samples[0]['vxAbsTicks'])
if r.get('release_watchdog_ticks') and r['observed_tick_hz']>0:r['release_watchdog_observed_ms']=1000*r['release_watchdog_ticks']/r['observed_tick_hz']
r['native_enable_evidence']='vxbSysClkEnable0x002f13e0 loads handle+4 frequency;0x002f13e8 loads handle+0x14 rate;0x002f13f0 divwu computes initial DEC interval. Later tickless scheduling may change handle+0x68 reload.'
r['nominal_release_ms']=1000*r.get('release_watchdog_ticks',0)/r['handle_rate_hz'] if r.get('handle_rate_hz') else None
r['registers']=qmp('human-monitor-command',{'command-line':'info registers'})
a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({k:v for k,v in r.items() if k not in ('registers','samples','handle_words')},indent=2));f.close();s.close()
