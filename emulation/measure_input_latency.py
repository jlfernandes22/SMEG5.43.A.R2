#!/usr/bin/env python3
"""Measure real QMP input-to-native-framebuffer change and QEMU thread load.

Does not change guest code, acceleration, affinity, or firmware. --click sends
one real absolute pointer click. Choose an ROI that changes in response to that
click and stays still otherwise. The metric is framebuffer observation, not a
physical laptop display/photodiode measurement; animation can confound it.
"""
import argparse, hashlib, json, os, re, socket, struct, tempfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--socket', type=Path, default=ROOT/'artifacts/phase3/interactive.qmp')
p.add_argument('--output', type=Path, default=ROOT/'artifacts/phase3/input-latency.json')
p.add_argument('--click', nargs=2, type=int, metavar=('X','Y'))
p.add_argument('--screenshot', type=Path)
p.add_argument('--after-screenshot', type=Path)
p.add_argument('--inspect-diu', action='store_true')
p.add_argument('--inspect-touch', action='store_true')
p.add_argument('--roi', nargs=4, type=int, default=[0,0,800,480], metavar=('X','Y','W','H'))
p.add_argument('--hold-ms', type=float, default=40)
p.add_argument('--timeout-ms', type=float, default=3000)
p.add_argument('--poll-ms', type=float, default=10)
p.add_argument('--baseline-ms', type=float, default=300)
p.add_argument('--profile-seconds', type=float, default=2)
p.add_argument('--touch-log', type=Path)
a = p.parse_args()
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(10); s.connect(str(a.socket))
pid, uid, gid = struct.unpack('3i',s.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
f=s.makefile('rb'); greeting=json.loads(f.readline()); serial=0

def qmp(name,args=None):
    global serial
    serial+=1; msg={'execute':name,'id':serial}
    if args is not None: msg['arguments']=args
    s.sendall((json.dumps(msg)+'\n').encode())
    while True:
        line=f.readline()
        if not line: raise RuntimeError('QMP disconnected')
        reply=json.loads(line)
        if reply.get('id')!=serial: continue
        if 'error' in reply: raise RuntimeError(reply['error'])
        return reply.get('return')

qmp('qmp_capabilities')
result={'schema':1,'host_arch':os.uname().machine,'qemu_pid':pid,'qemu_version':greeting['QMP']['version'],
        'status':qmp('query-status'),'vcpus':qmp('query-cpus-fast'),
        'measurement':'QMP input command to observed native framebuffer change; excludes physical display scanout'}

if a.screenshot:
    qmp('screendump',{'filename':str(a.screenshot.resolve())})
if a.inspect_diu or a.inspect_touch:
    def words(address,count):
        text=qmp('human-monitor-command',{'command-line':f'xp /{count}wx {address:#x}'})
        values=[]
        for line in text.splitlines():
            if ':' in line:values.extend(int(x,16) for x in re.findall(r'0x([0-9a-fA-F]+)',line.split(':',1)[1]))
        return values
    if a.inspect_touch:
        ctrl=words(0x036777dc,1)[0]
        result['touch_timing']={'ctrl':hex(ctrl),'ctrl_a8_ac':words(ctrl+0xa8,2) if ctrl else []}
    descriptors=words(0x80002100,3)
    result['diu']={'descriptor_registers':[hex(x) for x in descriptors],
                   'registers2100_213c':words(0x80002100,16),'areas':[]}
    for index,address in enumerate(descriptors):
        if 0<address<0x20000000:
            be=words(address,10)
            le=[int.from_bytes(x.to_bytes(4,'big'),'little') for x in be]
            result['diu']['areas'].append({'plane':index,'address':hex(address),
                'raw_be_words':[hex(x) for x in be], 'descriptor_le_words':[hex(x) for x in le]})

def proc_sample():
    out={}
    for d in Path(f'/proc/{pid}/task').glob('*'):
        try:
            raw=(d/'stat').read_text(); fields=raw[raw.rfind(')')+2:].split()
            status=(d/'status').read_text()
            out[int(d.name)]={'name':(d/'comm').read_text().strip(),
                'ticks':int(fields[11])+int(fields[12]),'processor':int(fields[36]),
                'allowed':re.search(r'^Cpus_allowed_list:\s*(.*)',status,re.M).group(1),
                'affinity':sorted(os.sched_getaffinity(int(d.name)))}
        except (OSError,ValueError,AttributeError): pass
    return out

def host_cpu_sample():
    out={}
    for line in Path('/proc/stat').read_text().splitlines():
        fields=line.split()
        if fields and re.fullmatch(r'cpu\d+',fields[0]):
            values=list(map(int,fields[1:9]))
            out[int(fields[0][3:])]=(sum(values),values[3]+values[4])
    return out

start=time.monotonic(); before=proc_sample(); cpu_before=host_cpu_sample()
if a.profile_seconds>0: time.sleep(a.profile_seconds)
after=proc_sample(); cpu_after=host_cpu_sample(); elapsed=time.monotonic()-start; hz=os.sysconf('SC_CLK_TCK')
result['host_cpu_busy_percent']={}
for cpu,(total,idle) in cpu_after.items():
    old_total,old_idle=cpu_before.get(cpu,(total,idle));delta=total-old_total
    if delta:result['host_cpu_busy_percent'][str(cpu)]=round(100*(1-(idle-old_idle)/delta),2)
loads=[]
for tid,item in after.items():
    item=dict(item); item['tid']=tid
    item['cpu_percent']=round(100*(item['ticks']-before.get(tid,item)['ticks'])/hz/elapsed,2)
    loads.append(item)
result['thread_profile']={'elapsed_seconds':elapsed,'cpu_load_sample_valid':a.profile_seconds>=0.1,'threads':sorted(loads,key=lambda x:-x['cpu_percent'])}
result['topology']={}
for c in sorted({cpu for item in after.values() for cpu in item['affinity']}):
    topo=Path(f'/sys/devices/system/cpu/cpu{c}/topology')
    try: result['topology'][str(c)]={'core':(topo/'core_id').read_text().strip(),
            'siblings':(topo/'thread_siblings_list').read_text().strip()}
    except OSError: pass

if a.click:
    x,y=a.click; rx,ry,rw,rh=a.roi
    if not (0<=x<800 and 0<=y<480 and 0<=rx<800 and 0<=ry<480 and rw>0 and rh>0 and rx+rw<=800 and ry+rh<=480):
        p.error('click/ROI must lie inside 800x480')
    def snapshot(path):
        t0=time.monotonic_ns(); qmp('screendump',{'filename':str(path)}); t1=time.monotonic_ns()
        b=path.read_bytes(); match=re.match(rb'P6\s+(\d+)\s+(\d+)\s+255\s',b)
        if not match: raise RuntimeError('Expected QEMU P6 RGB screendump')
        width,height=map(int,match.groups()); pixels=b[match.end():]
        if (width,height)!=(800,480) or len(pixels)!=width*height*3: raise RuntimeError('Unexpected framebuffer geometry')
        roi=b''.join(pixels[(row*width+rx)*3:(row*width+rx+rw)*3] for row in range(ry,ry+rh))
        return t0,t1,roi
    with tempfile.TemporaryDirectory(prefix='smeg-latency-') as temp:
        path=Path(temp)/'frame.ppm'; history=[]; end=time.monotonic()+a.baseline_ms/1000
        while not history or time.monotonic()<end:
            history.append(snapshot(path)); time.sleep(a.poll_ms/1000)
        reference=history[-1][2]; baseline_hashes={hashlib.sha256(item[2]).hexdigest() for item in history}
        result['baseline']={'samples':len(history),'unique_roi_frames':len(baseline_hashes),
             'stable':len(baseline_hashes)==1,'roi':a.roi,
             'capture_ms':[round((end-start)/1e6,3) for start,end,_ in history]}
        press_start=time.monotonic_ns()
        qmp('input-send-event',{'events':[
            {'type':'abs','data':{'axis':'x','value':round(x*32767/799)}},
            {'type':'abs','data':{'axis':'y','value':round(y*32767/479)}},
            {'type':'btn','data':{'button':'left','down':True}}]})
        press_ack=time.monotonic_ns(); release_start=release_ack=None; observations=[]
        deadline=press_start+int(a.timeout_ms*1e6); previous_end=press_ack; first=None; press_first=None; release_first=None; last_frame=reference; release_reference=reference
        try:
            while time.monotonic_ns()<deadline:
                if release_start is None and time.monotonic_ns()-press_start>=a.hold_ms*1e6:
                    release_reference=last_frame
                    release_start=time.monotonic_ns()
                    qmp('input-send-event',{'events':[{'type':'btn','data':{'button':'left','down':False}}]})
                    release_ack=time.monotonic_ns()
                start,end,frame=snapshot(path)
                different=frame!=reference
                changed=0 if not different else (sum(frame[i:i+3]!=reference[i:i+3] for i in range(0,len(frame),3)) if first is None else None)
                sample={'capture_start_ms':(start-press_start)/1e6,'capture_end_ms':(end-press_start)/1e6,'changed_pixels':changed,'frame_changed_from_baseline':different}
                observations.append(sample)
                if different and first is None:
                    first={'observation_upper_ms':(end-press_start)/1e6,
                           'previous_observation_end_ms':(previous_end-press_start)/1e6,
                           'changed_pixels':changed}
                if release_start is None and different and press_first is None:
                    press_first={'observation_upper_ms':(end-press_start)/1e6}
                if release_start is not None and frame!=release_reference and release_first is None:
                    release_first={'observation_upper_ms':(end-release_start)/1e6,
                        'capture_start_ms':(start-release_start)/1e6}
                last_frame=frame
                previous_end=end
                if release_first and end-release_start>=250000000: break
                time.sleep(a.poll_ms/1000)
        finally:
            if release_start is None:
                release_start=time.monotonic_ns()
                qmp('input-send-event',{'events':[{'type':'btn','data':{'button':'left','down':False}}]})
                release_ack=time.monotonic_ns()
        result['click']={'position':a.click,'press_host_ns':press_start,'press_ack_ms':(press_ack-press_start)/1e6,
             'actual_hold_ms':(release_start-press_start)/1e6,'release_ack_ms':(release_ack-release_start)/1e6,
             'first_change':first,'press_feedback':press_first,'release_transition':release_first,'observations':observations,
             'causal_limit':'Unstable baseline/animations can produce unrelated changes; inspect ROI and compare idle controls.'}
        if a.touch_log and a.touch_log.is_file():
            events=[]
            for line in a.touch_log.open(errors='replace'):
                if 'touch edge' not in line and 'touch DMA' not in line: continue
                m=re.search(r'host_ns=(\d+)',line)
                if m and press_start-10000000<=int(m[1])<=previous_end+100000000:
                    events.append(line.strip())
            result['click']['native_touch_trace']=events
if a.after_screenshot:qmp('screendump',{'filename':str(a.after_screenshot.resolve())})
qmp('query-status'); f.close(); s.close(); a.output.parent.mkdir(parents=True,exist_ok=True)
a.output.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'output':str(a.output),'pid':pid,'vcpus':result['vcpus'],
    'top_threads':[{k:t[k] for k in ('tid','name','cpu_percent','processor','allowed')} for t in result['thread_profile']['threads'][:6]], 'click':result.get('click',{}).get('first_change')},indent=2))
