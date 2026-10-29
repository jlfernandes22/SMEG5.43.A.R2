#!/usr/bin/env python3
"""Bounded supervision of one existing native updater; never starts a VM.

No guest memory writes or guest function injection. Captures native output;
does not infer installation success from a running VM or a startup logo.
"""
import argparse
import json
from pathlib import Path
import re
import time
from run_usb_probe import QMP

ROOT=Path(__file__).resolve().parents[1]


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--prefix',required=True);p.add_argument('--run',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--seconds',type=int,default=1800);a=p.parse_args()
    assert a.prefix.startswith('/tmp/smeg-p8-') and 1<=a.seconds<=3600
    assert a.run.resolve().is_relative_to(ROOT/'artifacts') and a.output.resolve().is_relative_to(ROOT/'artifacts/phase13')
    a.output.mkdir(parents=True,exist_ok=False)
    start=time.monotonic();report={'existing_VM_only':True,'physical_device_access':False,'RAM_patches':False,'samples':[],'installation_verified':False}
    try:
        while time.monotonic()-start<a.seconds:
            q=None
            try:
                q=QMP(a.prefix+'.qmp');status=q.call('query-status')
                index=len(report['samples']);q.call('screendump',{'filename':str((a.output/f'capture-{index:03d}.png').resolve()),'format':'png'})
                log=(a.run/'serial.log').read_text(errors='replace')
                report['samples'].append({'elapsed':round(time.monotonic()-start),'guest_status':status,'serial_bytes':len(log),
                    'native_marker_counts':{s:len(re.findall(re.escape(s),log,re.I))for s in ['UpgradeStart','PHASE','Relaunch For256','Relaunch For 256','must restart','TIMEOUT']}})
            except (OSError,EOFError) as e:
                report['VM_connection_ended']=repr(e);break
            finally:
                if q:q.close()
            (a.output/'progress.json').write_text(json.dumps(report,indent=2)+'\n')
            if (a.output/'STOP').exists():report['stop_requested_by_primary_agent']=True;break
            for _ in range(30):
                if (a.output/'STOP').exists():break
                time.sleep(1)
    finally:
        q=None
        try:q=QMP(a.prefix+'.qmp');q.call('quit');report['VM_stopped_cleanly']=True
        except (OSError,EOFError):pass
        finally:
            if q:q.close()
        report['elapsed_seconds']=round(time.monotonic()-start)
        report['conclusion']='Evidence capture only. Native installation and cold-boot contents require separate verification.'
        (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':main()
