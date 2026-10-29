#!/usr/bin/env python3
"""Repeat measured real SMEG menu taps, retaining idle trials and failures."""
import argparse
import json
import math
import statistics
import subprocess
import sys
import time
from pathlib import Path

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--tag', required=True)
p.add_argument('--count', type=int, default=20)
p.add_argument('--idle-seconds', type=float, default=20)
a=p.parse_args()
root=Path(__file__).resolve().parent.parent
out=root/'artifacts/phase3'
rows=[]
for i in range(a.count):
    idle=a.idle_seconds if i in {a.count//2, a.count-1} else 0
    if idle: time.sleep(idle)
    path=out/f'{a.tag}-{i:02}.json'
    cmd=[sys.executable,str(root/'emulation/measure_input_latency.py'),
         '--click','30','230','--roi','0','80','800','370',
         '--hold-ms','80','--timeout-ms','2000','--poll-ms','5',
         '--baseline-ms','200','--profile-seconds','0',
         '--touch-log',str(out/'interactive.qemu.log'),'--output',str(path)]
    subprocess.run(cmd,check=True,stdout=subprocess.DEVNULL)
    d=json.loads(path.read_text()); c=d['click']
    row={'trial':i,'idle_seconds':idle,'stable':d['baseline']['stable'],
         'press_ms':(c.get('press_feedback') or {}).get('observation_upper_ms'),
         'release_ms':(c.get('release_transition') or {}).get('observation_upper_ms'),
         'actual_hold_ms':c['actual_hold_ms'],'evidence':str(path)}
    rows.append(row);print(json.dumps(row),flush=True)

def summarize(name):
    values=sorted(r[name] for r in rows if r[name] is not None)
    return {'n':len(values),'misses':len(rows)-len(values),
            'median_ms':statistics.median(values) if values else None,
            'p95_ms':values[max(0,math.ceil(.95*len(values))-1)] if values else None,
            'max_ms':max(values) if values else None,
            'under100':sum(v<100 for v in values)}
result={'schema':1,'tag':a.tag,'count':a.count,'includes_idle_trials':True,
        'all_baselines_stable':all(r['stable'] for r in rows),
        'press':summarize('press_ms'),'release':summarize('release_ms'),'trials':rows,
        'metric':'QMP pointer events to changed native framebuffer; not physical panel latency'}
(out/f'{a.tag}-summary.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k!='trials'}),flush=True)
