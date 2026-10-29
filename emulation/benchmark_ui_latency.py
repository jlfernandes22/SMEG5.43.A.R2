#!/usr/bin/env python3
"""Repeat an explicitly selected real UI action and summarize misses/timing.

Use a control that is safe in both alternating UI states (e.g. SMEG's back
control). No latency is fabricated for a missed action. Cold trials remain in
full-sample p95/max; a separately labelled tail reports warm-sample behavior.
"""
import argparse,json,math,statistics,subprocess,sys
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--prefix',required=True,type=Path)
p.add_argument('--click',nargs=2,type=int,default=[30,230])
p.add_argument('--roi',nargs=4,type=int,default=[0,80,800,370])
p.add_argument('--holds-ms',nargs='+',type=float,default=[60,80])
p.add_argument('--samples',type=int,default=10)
p.add_argument('--timeout-ms',type=int,default=2500)
p.add_argument('--touch-log',type=Path,default=Path('artifacts/phase3/interactive.qemu.log'))
a=p.parse_args();items=[]
def summarize(rows):
    out={'count':len(rows),'unstable_baselines':sum(not x['stable'] for x in rows)}
    for label in ('press','release'):
        v=sorted(x[label+'_ms'] for x in rows if x[label+'_ms'] is not None)
        out[label]={'misses':sum(x[label+'_ms'] is None for x in rows),'successful':len(v),
                    'under100_count':sum(x<100 for x in v)}
        if v:out[label].update(median_ms=statistics.median(v),p95_ms=v[math.ceil(.95*len(v))-1],maximum_ms=max(v))
    return out
for i in range(a.samples):
    target=Path(str(a.prefix)+f'-{i:02d}.json');hold=a.holds_ms[i%len(a.holds_ms)]
    args=[sys.executable,str(Path(__file__).with_name('measure_input_latency.py')),
          '--click',*map(str,a.click),'--roi',*map(str,a.roi),'--hold-ms',str(hold),
          '--profile-seconds','0','--baseline-ms','200','--poll-ms','5',
          '--timeout-ms',str(a.timeout_ms),'--touch-log',str(a.touch_log),'--output',str(target)]
    if i==0:args+=['--inspect-touch']
    run=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    if run.returncode:raise RuntimeError(run.stderr or run.stdout)
    j=json.loads(target.read_text());c=j['click'];events=c.get('native_touch_trace',[])
    item={'trial':i,'artifact':str(target),'pid':j['qemu_pid'],'stable':j['baseline']['stable'],
          'requested_hold_ms':hold,'actual_hold_ms':c['actual_hold_ms'],
          'press_ms':c['press_feedback']['observation_upper_ms'] if c['press_feedback'] else None,
          'release_ms':c['release_transition']['observation_upper_ms'] if c['release_transition'] else None}
    items.append(item);print(json.dumps(item),flush=True)
    summary={'trials':items,'all':summarize(items),'excluding_first_explicit_warm_view':summarize(items[1:])}
    Path(str(a.prefix)+'-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary),flush=True)
