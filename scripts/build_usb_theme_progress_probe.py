#!/usr/bin/env python3
"""Build a UI-only private QEMU probe, with no car/device writes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from smeg_db_inf import crc16
ROOT=Path(__file__).resolve().parents[1]

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--fail',action='store_true')
    p.add_argument('--ack-seconds',type=int,default=12)
    p.add_argument('--percent-demo',action='store_true')
    a=p.parse_args();out=a.output.resolve()
    if not 5<=a.ack_seconds<=300:p.error('Acknowledgement timeout must be 5..300 seconds')
    assert out.is_relative_to(ROOT/'artifacts/phase21') and not out.exists()
    out.mkdir(parents=True)
    from theme_progress_contract import write_contract
    contract=write_contract(ROOT,out)
    source=ROOT/'emulation/usb_theme_progress_probe.c';module=out/'progress.out'
    shutil.copyfile(source,out/'source.c')
    helper=ROOT/'emulation/theme_install_progress.h'
    shutil.copyfile(helper,out/'theme_install_progress.h')
    command=['clang','--target=powerpc-unknown-linux-gnu','-mbig-endian','-m32','-mlongcall','-ffreestanding','-fno-pic',
        '-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-msoft-float','-O2','-Wall','-Wextra','-Werror',
        f'-DTHEME_PROGRESS_ACK_SECONDS={a.ack_seconds}',*(['-DTHEME_PROGRESS_FAIL_TEST=1']if a.fail else []),
        *(['-DTHEME_PROGRESS_PERCENT_DEMO=1']if a.percent_demo else []),
        '-I',str(ROOT/'emulation'),'-I',str(out),'-c',str(source),'-o',str(module)]
    subprocess.run(command,check=True)
    payload=module.read_bytes()
    body=(f'{crc16(payload):04x}\r\nVER:SMEG5.43.A.R2\r\nTYPE:RELOCABLE\r\nID:0\r\nCOMPRESSED:NO\r\nSIZE:{len(payload)}\r\nENTRY:YES\r\n').encode()
    doctor=b'0000\r\nACTION:TemporaryBootRom\r\nLOAD_AND_EXECUTE:/bd0/FLYING/progress.out\r\n'
    image=out/'usb.raw';shutil.copyfile(ROOT/'artifacts/phase21/original-checker-readonly-v3/usb.raw',image)
    spec=str(image)+'@@1048576';env=dict(os.environ,MTOOLS_SKIP_CHECK='1')
    def run(*cmd):return subprocess.run(cmd,capture_output=True,check=True,env=env)
    run('mdel','-i',spec,'::/FLYING/checksrc.out','::/FLYING/checksrc.out.inf','::/FLYING/doctor_smeg_plus_i.inf')
    files={'FLYING/progress.out':payload,'FLYING/progress.out.inf':f'{crc16(body):04x}'.encode()+body,
        'FLYING/doctor_smeg_plus_i.inf':f'{crc16(doctor):04x}'.encode()+doctor}
    with tempfile.TemporaryDirectory()as td:
        for i,(name,data)in enumerate(files.items()):
            t=Path(td)/str(i);t.write_bytes(data);run('mcopy','-i',spec,str(t),'::/'+name)
            assert run('mtype','-i',spec,'::/'+name).stdout==data
    report=dict(emulator_only=True,physical_car_approved=False,configuration_setters=False,NAND_write_APIs=False,
        progress_contract=contract,failure_test=a.fail,percent_demo=a.percent_demo,
        acknowledgement_seconds=a.ack_seconds,image=str(image),image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),compile_command=command,
        source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        shared_helper_sha256=hashlib.sha256(helper.read_bytes()).hexdigest())
    (out/'usb.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':main()
