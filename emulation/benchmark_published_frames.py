#!/usr/bin/env python3
"""Measure device-edge to real console publication, without screenshot polling.

The board logs a timestamp and hash after updating the real QEMU display surface.
This measures native framebuffer response, excluding compositor/panel scanout.
It retains failures, unstable idle controls, and after-idle trials.
"""
import argparse,json,math,re,socket,statistics,time
from pathlib import Path

root=Path(__file__).resolve().parent.parent
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--tag',required=True)
p.add_argument('--count',type=int,default=20)
p.add_argument('--hold-ms',type=float,default=80)
p.add_argument('--idle-seconds',type=float,default=15)
p.add_argument('--timeout-ms',type=float,default=2000)
a=p.parse_args(); out=root/'artifacts/phase3'
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(5)
s.connect(str(out/'interactive.qmp'));f=s.makefile('rb');json.loads(f.readline());serial=0

def qmp(name,args=None):
 global serial
 serial+=1; msg={'execute':name,'id':serial}
 if args is not None:msg['arguments']=args
 s.sendall((json.dumps(msg)+'\n').encode())
 while True:
  line=f.readline()
  if not line:raise RuntimeError('QMP disconnected')
  r=json.loads(line)
  if r.get('id')==serial:
   if 'error'in r:raise RuntimeError(r['error'])
   return r.get('return')
qmp('qmp_capabilities')
stream=(out/'interactive.qemu.log').open(errors='replace')
stream.seek(max(0,(out/'interactive.qemu.log').stat().st_size-65536))
frames=[];edges=[];partial=''

def update():
 global partial
 text=partial+stream.read(); lines=text.split('\n');partial=lines.pop()
 for l in lines:
  m=re.fullmatch(r'SMEG display publish host_ns=(\d+) roi_sha256=([0-9a-f]{64})',l)
  if m:frames.append({'ns':int(m[1]),'hash':m[2]})
  m=re.search(r'SMEG touch edge down=(\d+) host_ns=(\d+)',l)
  if m:edges.append({'down':int(m[1]),'ns':int(m[2])})

def pause(seconds):
 end=time.monotonic()+seconds
 while time.monotonic()<end:update();time.sleep(.001)
 update()

def button(down):
 qmp('input-send-event',{'events':[
  {'type':'abs','data':{'axis':'x','value':round(30*32767/799)}},
  {'type':'abs','data':{'axis':'y','value':round(230*32767/479)}},
  {'type':'btn','data':{'button':'left','down':down}}]})
update()
if not frames:raise RuntimeError('No published-frame hashes: launch with SMEG_TRACE_TOUCH=1 and wait for UI')
trials=[]
for i in range(a.count):
 idle=a.idle_seconds if i in {0,a.count//2,a.count-1} else .1
 pause(idle)
 baseline=frames[-1]['hash'];start_idle=time.monotonic_ns();pause(.2)
 stable=all(x['hash']==baseline for x in frames if x['ns']>=start_idle)
 start=time.monotonic_ns();button(True)
 try:
  remaining=a.hold_ms/1000-(time.monotonic_ns()-start)/1e9
  if remaining>0:pause(remaining)
 finally:button(False)
 update()
 deadline=time.monotonic()+a.timeout_ms/1000
 while time.monotonic()<deadline:
  update();ups=[e for e in edges if e['ns']>=start and not e['down']]
  if ups and time.monotonic_ns()-ups[-1]['ns']>=400000000:break
  time.sleep(.001)
 update(); downs=[e for e in edges if e['ns']>=start and e['down']];ups=[e for e in edges if e['ns']>=start and not e['down']]
 down=downs[0]['ns']if downs else None;up=ups[0]['ns']if ups else None
 press=next((x for x in frames if down is not None and up is not None and down<=x['ns']<up and x['hash']!=baseline),None)
 before_up=[x for x in frames if up is not None and x['ns']<up]
 reference=before_up[-1]['hash']if before_up else baseline
 release=next((x for x in frames if up is not None and x['ns']>=up and x['hash']!=reference),None)
 nav=next((x for x in frames if up is not None and x['ns']>=up and x['hash']not in {reference,baseline}),None)
 row={'trial':i,'idle_seconds':idle,'stable':stable,'down_ns':down,'up_ns':up,
      'press_ms':(press['ns']-down)/1e6 if press else None,
      'release_ms':(release['ns']-up)/1e6 if release else None,
      'navigation_ms':(nav['ns']-up)/1e6 if nav else None,
      'frames':[x for x in frames if x['ns']>=start]}
 trials.append(row);print(json.dumps({k:v for k,v in row.items()if k!='frames'}),flush=True)

def stats(key):
 vals=sorted(x[key]for x in trials if x[key]is not None)
 return {'n':len(vals),'misses':len(trials)-len(vals),'median_ms':statistics.median(vals)if vals else None,
         'p95_ms':vals[max(0,math.ceil(.95*len(vals))-1)]if vals else None,
         'max_ms':max(vals)if vals else None,'under100':sum(v<100 for v in vals)}
r={'schema':1,'metric':'device edge to native display-surface publication; excludes physical panel/compositor',
   'screenshot_polling':False,'tag':a.tag,'trials':trials,'all_idle_controls_stable':all(t['stable']for t in trials),
   'press':stats('press_ms'),'release':stats('release_ms'),'navigation':stats('navigation_ms')}
(out/f'{a.tag}.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({k:v for k,v in r.items()if k!='trials'}),flush=True)
f.close();s.close();stream.close()
