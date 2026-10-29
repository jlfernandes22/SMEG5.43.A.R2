#!/usr/bin/env python3
"""Reversible host-affinity tuning after renderer worker creation.

No firmware or guest scheduler changes. Only the QEMU main thread and its one
vCPU thread are pinned. --isolate-renderer optionally reserves those physical
cores by moving Mesa workers to other cores. The helper waits for a settled
renderer pool before changing affinity,
so worker creation cannot inherit an accidentally single-core CPU affinity.
"""
import argparse, json, os, re, socket, struct, time
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--pid',type=int)
p.add_argument('--socket',type=Path,default=ROOT/'artifacts/phase3/interactive.qmp')
p.add_argument('--once',action='store_true',help='apply once and exit (default also exits after applying)')
p.add_argument('--main-cpu',type=int,default=int(os.environ.get('SMEG_MAIN_CPU','2')))
p.add_argument('--vcpu-cpu',type=int,default=int(os.environ.get('SMEG_VCPU_CPU','3')))
p.add_argument('--auto',action='store_true',help='choose least-busy eligible distinct physical cores')
p.add_argument('--timeout',type=float,default=120)
p.add_argument('--renderer-ready-log',type=Path,help='allow confirmed hardware EGL renderer after thread pool settles')
p.add_argument('--dry-run',action='store_true')
p.add_argument('--isolate-renderer',action='store_true',help='keep Mesa workers off the two UI/vCPU physical cores, including SMT siblings')
p.add_argument('--output',type=Path,default=ROOT/'artifacts/phase3/ui-affinity.json')
p.add_argument('--restore',type=Path,help='restore original two thread affinities from a previous output')
a=p.parse_args()

def task_start(pid,tid):
    b=Path(f'/proc/{pid}/task/{tid}/stat').read_text();return int(b[b.rfind(')')+2:].split()[19])
def task_names(pid):
    out={}
    for path in Path(f'/proc/{pid}/task').glob('*'):
        try:out[int(path.name)]=(path/'comm').read_text().strip()
        except OSError:pass
    return out

def physical(cpu):
    d=Path(f'/sys/devices/system/cpu/cpu{cpu}/topology')
    return ((d/'physical_package_id').read_text().strip(),(d/'core_id').read_text().strip())

def cpu_load():
    out={}
    for l in Path('/proc/stat').read_text().splitlines():
        f=l.split()
        if f and re.fullmatch(r'cpu\d+',f[0]):
            v=list(map(int,f[1:9]));out[int(f[0][3:])]=(sum(v),v[3]+v[4])
    return out

if a.restore:
    saved=json.loads(a.restore.read_text());pid=saved['pid'];changes=[]
    for item in saved['changes']:
        tid=item['tid']
        if task_start(pid,tid)!=item['start_ticks']:raise RuntimeError('PID/TID was reused; refusing stale restore')
        original=set(item['before'])
        if not a.dry_run:os.sched_setaffinity(tid,original)
        changes.append({'tid':tid,'restored':sorted(original)})
    print(json.dumps({'pid':pid,'dry_run':a.dry_run,'restore':changes},indent=2));raise SystemExit

s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(10)
connect_deadline=time.monotonic()+a.timeout
while True:
    try:
        s.connect(str(a.socket))
        break
    except (FileNotFoundError,ConnectionRefusedError):
        if time.monotonic()>=connect_deadline:
            raise RuntimeError('QEMU monitor did not become ready; no affinity changed')
        time.sleep(.1)
pid=struct.unpack('3i',s.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[0]
if a.pid is not None and a.pid!=pid:raise RuntimeError('Provided PID does not own this QMP socket')
f=s.makefile('rb');json.loads(f.readline());serial=0

def qmp(name):
    global serial
    serial+=1;s.sendall((json.dumps({'execute':name,'id':serial})+'\n').encode())
    while True:
        line=f.readline()
        if not line:raise RuntimeError('QMP disconnected')
        j=json.loads(line)
        if j.get('id')==serial:
            if 'error'in j:raise RuntimeError(j['error'])
            return j['return']
qmp('qmp_capabilities');cpus=qmp('query-cpus-fast');f.close();s.close()
if len(cpus)!=1 or cpus[0].get('target')!='ppc':raise RuntimeError('Expected the single-vCPU SMEG PPC machine')
vcpu=cpus[0]['thread-id']
if 'qemu-system-ppc' not in Path(f'/proc/{pid}/comm').read_text():raise RuntimeError('Unexpected process name')
environ=dict(item.split('=',1) for item in Path(f'/proc/{pid}/environ').read_bytes().decode(errors='replace').split('\0') if '=' in item)
expected=max(1,int(environ.get('LP_NUM_THREADS','1')))
end=time.monotonic()+a.timeout;last=None;settled=None;workers={};ready_mode=None
while time.monotonic()<end:
    names=task_names(pid)
    workers={tid:name for tid,name in names.items() if 'llvmpipe' in name.lower()}
    hardware_ready=False
    if a.renderer_ready_log and a.renderer_ready_log.is_file():
        text=a.renderer_ready_log.read_text(errors='replace')
        renderer=next((line for line in text.splitlines() if 'SMEG software GL:' in line or 'SMEG host GL (' in line),'')
        hardware_ready=bool(renderer and 'llvmpipe' not in renderer.lower() and
                            any(vendor in renderer.lower() for vendor in ('nvidia','radeon','intel','amd')))
    signature=tuple(sorted(names)) if hardware_ready else tuple(sorted(workers))
    if len(workers)>=expected or hardware_ready:
        ready_mode='hardware EGL initialized; complete host thread set stable' if hardware_ready else 'llvmpipe workers initialized'

        if signature!=last:settled=time.monotonic();last=signature
        elif settled is not None and time.monotonic()-settled>=1:break
    else:settled=None;last=signature
    time.sleep(.2)
else:raise RuntimeError(f'Mesa llvmpipe pool not ready: found {len(workers)}, expected >= {expected}; no affinity changed')

main_allowed=set(os.sched_getaffinity(pid));vcpu_allowed=set(os.sched_getaffinity(vcpu))
if a.auto:
    before=cpu_load();time.sleep(1);after=cpu_load();busy={}
    for cpu,(total,idle) in after.items():
        t0,i0=before.get(cpu,(total,idle));busy[cpu]=1-(idle-i0)/max(1,total-t0)
    candidates=[]
    for main in main_allowed:
        for guest in vcpu_allowed:
            if physical(main)!=physical(guest):
                candidates.append((busy.get(main,1)+busy.get(guest,1),main,guest))
    if not candidates:raise RuntimeError('No distinct allowed physical CPU cores')
    _,a.main_cpu,a.vcpu_cpu=min(candidates)
if a.main_cpu not in main_allowed or a.vcpu_cpu not in vcpu_allowed:raise RuntimeError('Requested CPU outside current allowed affinity')
if physical(a.main_cpu)==physical(a.vcpu_cpu):raise RuntimeError('Choose different physical cores, not SMT siblings')
worker_affinity={str(tid):sorted(os.sched_getaffinity(tid)) for tid in workers}
if any(len(c)<2 for c in worker_affinity.values()):raise RuntimeError('Renderer workers already restricted to one CPU; no affinity changed')
changes=[]
for tid,cpu,allowed in [(pid,a.main_cpu,main_allowed),(vcpu,a.vcpu_cpu,vcpu_allowed)]:
    changes.append({'tid':tid,'start_ticks':task_start(pid,tid),'before':sorted(allowed),'after':[cpu]})
if a.isolate_renderer:
    reserved={physical(a.main_cpu),physical(a.vcpu_cpu)}
    for tid in workers:
        allowed=set(os.sched_getaffinity(tid))
        eligible={cpu for cpu in allowed if physical(cpu) not in reserved}
        if not eligible:raise RuntimeError('No separate CPU cores remain for Mesa workers')
        changes.append({'tid':tid,'start_ticks':task_start(pid,tid),
                        'before':sorted(allowed),'after':sorted(eligible)})
result={'pid':pid,'dry_run':a.dry_run,'renderer_readiness':ready_mode,'mesa_workers':workers,'mesa_affinity_unchanged':worker_affinity,'changes':changes,
        'caution':'Optional experiment: compare measured native input latency before enabling by default.'}
# Persist restoration data before either reversible mutation.
a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2)+'\n')
if not a.dry_run:
    try:
        for item in changes:os.sched_setaffinity(item['tid'],set(item['after']))
    except Exception:
        for item in changes:os.sched_setaffinity(item['tid'],set(item['before']))
        raise
if a.isolate_renderer:
    result['mesa_affinity_unchanged']=False
    result['renderer_original_affinities']=worker_affinity
    a.output.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
