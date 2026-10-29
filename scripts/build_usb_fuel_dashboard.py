#!/usr/bin/env python3
"""Build separate QEMU-only local Connect Apps content and a one-key portal test.

Public DGEG responses must already be cached by the host. This tool has no
network access, never writes a device, and does not alter any theme image.
"""
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
def sha(data):return hashlib.sha256(data).hexdigest()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--cache',type=Path,default=ROOT/'artifacts/phase20/custom-apps-dgeg')
    parser.add_argument('--install-local',action='store_true',help='QEMU experiment: add a new SYSTEM HTML file and point only the portal key to it')
    a=parser.parse_args();out=a.output.resolve()
    assert out.is_relative_to(ROOT/'artifacts/phase20') and not out.exists()
    out.mkdir(parents=True)
    cache=a.cache.resolve()
    assert cache.is_relative_to(ROOT/'artifacts/phase20') and cache.is_dir()
    fuels=[];sources=[]
    for data_name,fetch_name in [('stations-response.json','fetch.json'),('petrol-response.json','petrol-fetch.json')]:
        raw=(cache/data_name).read_bytes();data=json.loads(raw);fetch=json.loads((cache/fetch_name).read_text())
        assert data['status']is True and len(data['resultado'])==5
        assert fetch['url'].startswith('https://precoscombustiveis.dgeg.gov.pt/api/PrecoComb/PesquisarPostos?')
        fuels.append(dict(stations=data['resultado'],fetched_utc=fetch['fetched_utc']))
        sources.append(dict(**fetch,response_sha256=sha(raw)))
    snapshot=dict(fuels=fuels,fetched_utc=min(f['fetched_utc']for f in fuels))
    html=(ROOT/'emulation/local_apps/fuel.html').read_text()
    assert html.count('__FUEL_SNAPSHOT__')==1
    html=html.replace('__FUEL_SNAPSHOT__',json.dumps(snapshot,ensure_ascii=True).replace('</','<\\/')).encode()
    (out/'index.html').write_bytes(html);(out/'snapshot.json').write_text(json.dumps(snapshot,indent=2)+'\n')
    template=ROOT/'artifacts/phase11/usb-capabilities/portal-path/usb.raw'
    image=out/'usb.raw';shutil.copyfile(template,image)
    spec=str(image)+'@@1048576';env=dict(os.environ,MTOOLS_SKIP_CHECK='1')
    def run(*args):return subprocess.run(args,check=True,capture_output=True,env=env)
    # Recompile the existing individually guarded one-key API helper. Its
    # sole intended setting is internet.URL_PSA_portal, on a private VM clone.
    header=ROOT/'artifacts/phase8/usb-maintenance/usb_portal_api_fingerprints.h'
    shutil.copyfile(header,out/header.name)
    source=ROOT/('emulation/usb_install_fuel_portal_sandbox.c'if a.install_local else'emulation/usb_set_portal_sandbox.c');module=out/'sandbox_set_portal.out'
    if a.install_local:
        from build_usb_resource_probe import fnv
        shutil.copyfile(ROOT/'artifacts/phase20/theme-activation-probe-v3/theme_preview_fs_contract.h',out/'theme_preview_fs_contract.h')
        (out/'portal_content_contract.h').write_text(f'#define PORTAL_CONTENT_BYTES {len(html)}u\n#define PORTAL_CONTENT_HASH 0x{fnv(html):08x}u\n')
    cmd=['clang','--target=powerpc-unknown-linux-gnu','-mbig-endian','-m32','-mlongcall','-ffreestanding','-fno-pic',
         '-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-msoft-float',
         '-I',str(out),'-I',str(ROOT/'emulation'),'-O2','-Wall','-Wextra','-Werror','-c',str(source),'-o',str(module)]
    subprocess.run(cmd,check=True);payload=module.read_bytes()
    body=(f'{crc16(payload):04x}\r\nVER:SMEG5.43.A.R2\r\nTYPE:RELOCABLE\r\nID:0\r\nCOMPRESSED:NO\r\nSIZE:{len(payload)}\r\nENTRY:YES\r\n').encode()
    files={'SMEG_CAP/index.html':html,'FLYING/sandbox_set_portal.out':payload,
           'FLYING/sandbox_set_portal.out.inf':f'{crc16(body):04x}'.encode()+body}
    with tempfile.TemporaryDirectory()as td:
        for i,(name,data)in enumerate(files.items()):
            p=Path(td)/str(i);p.write_bytes(data);run('mcopy','-o','-i',spec,str(p),'::/'+name)
            assert run('mtype','-i',spec,'::/'+name).stdout==data
    assert subprocess.run(['mdir','-i',spec,'::/SMEG_BACKUP'],capture_output=True,env=env).returncode!=0
    report=dict(emulator_only=True,physical_device_access=False,physical_car_approved=False,
        local_HTML=True,guest_network_required=False,live_price_feed=False,source=sources,
        intended_parameter_change={'internet.URL_PSA_portal':{'from':'/SYSTEM/internet_default/portal/index.html','to':'/SYSTEM/internet_default/customfuel/index.html'if a.install_local else'/bd0/SMEG_CAP/index.html'}},
        new_SYSTEM_HTML_file='/SYSTEM/internet_default/customfuel/index.html'if a.install_local else None,
        other_intended_setting_changes=[],firmware_or_theme_payloads=False,
        image=str(image),image_sha256=sha(image.read_bytes()),compile_command=cmd,
        files=[dict(path=n,bytes=len(d),sha256=sha(d))for n,d in files.items()])
    (out/'usb.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(dict(image=str(image),offline=True)))

if __name__=='__main__':main()
