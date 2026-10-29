#!/usr/bin/env python3
"""Read native updater progress without injected calls or memory writes."""
import argparse,json,re,struct,time
from pathlib import Path
from run_usb_probe import QMP

p=argparse.ArgumentParser(description=__doc__);p.add_argument('--prefix',required=True);p.add_argument('--output',type=Path);a=p.parse_args()
assert a.prefix.startswith('/tmp/smeg-')
if a.output:assert a.output.resolve().is_relative_to(Path(__file__).resolve().parents[1]/'artifacts/phase13') and not a.output.exists()
q=QMP(a.prefix+'.qmp');was_running=q.call('query-status').get('running',False)
j={'physical_device_access':False,'guest_memory_writes':False,'guest_function_calls_injected':False,'time_unix':time.time()}
try:
    q.call('stop')
    def mem(addr,n):
        assert 0x1000<=addr and addr+n<0x20000000 and 0<n<=256
        s=q.call('human-monitor-command',{'command-line':f'xp /{n}bx {addr:#x}'})
        raw=bytes(int(v,16)for l in s.splitlines()if ':'in l for v in re.findall(r'0x([0-9a-fA-F]{2})\b',l.split(':',1)[1]))
        assert len(raw)==n,(hex(addr),s)
        return raw
    def word(addr):return int.from_bytes(mem(addr,4),'big')
    base=q.call('qom-get',{'path':'/machine','property':'updater-gl-base'});assert 0x1000000<=base<0x1f000000
    code=mem(base+0x3c30,12);ins=struct.unpack('>III',code)
    assert ins[0]>>16==0x3d20 and ins[1]>>16==0x8069 and ins[2]==0x4e800020,code.hex()
    displacement=struct.unpack('>h',code[6:8])[0]
    global_addr=((ins[0]&0xffff)<<16)+displacement
    obj=word(global_addr);j.update(native_text_base=hex(base),singleton_global=hex(global_addr),instance=hex(obj),numeric_progress=word(obj+0xa8))
    for name,off in [('action',0x78),('phase',0x80),('progress',0x88)]:
        b=word(obj+off+4);record={'buffer':hex(b)}
        if b:
            record['native_length']=word(b+0x1d8)
            for charset,entry in [(2,0x98),(0,4),(1,0x10c),(3,0x1a0),(4,0x1bc)]:
                if mem(b+entry+16,1)[0]:
                    ptr=word(b+entry+4)
                    if 0x1000<=ptr<0x1fffff00:
                        raw=mem(ptr,192).split(b'\0')[0]
                        record.update(cached_charset=charset,cached_bytes=raw.hex(),text=raw.decode('utf-8',errors='replace'));break
        j[name]=record
except Exception as e:j['error']=repr(e)
finally:
    if was_running:q.call('cont')
    j['guest_resumed']=q.call('query-status').get('running',False);q.close()
    if a.output:a.output.write_text(json.dumps(j,indent=2)+'\n')
print(json.dumps(j,indent=2))
