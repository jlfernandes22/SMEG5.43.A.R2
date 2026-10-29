#!/usr/bin/env python3
"""Build QEMU-only regular-file USB image for the read-only native backup probe.

No physical block devices are accepted. CRC metadata is not a vendor signature.
This exercises the existing maintenance loader, not the firmware-update flow.
"""
import argparse
import hashlib
import json
import os
import struct
import subprocess
import tempfile
import gzip
from pathlib import Path
from smeg_db_inf import crc16

ROOT = Path(__file__).resolve().parents[1]


def write_api_checks(portal=False):
    names = [
        '_ZN6UP_MOD8InstanceEv',
        '_ZN6UP_MOD13GetConfigKeysERK9CMMStringS2_R9CMMUPKeys',
        '_ZN6UP_MOD22SetConfigKeysImmediateERK9CMMUPKeys',
        '_ZN9CMMStringC1EPKci28t_cmmstring_characterSetType25t_cmmstring_charOrStrType',
        '_ZN9CMMUPKeysC1Ev', '_ZNK9CMMUPKeys10GetKeyBoolERK9CMMStringS2_Rbi',
        '_ZN9CMMUPKeys10AddKeyBoolERK9CMMStringS2_bi', '_ZNK9CMMUPKeys9GetNbKeysEv',
        '_ZN9CMMUPKeysD1Ev', '_ZN9CMMStringD1Ev']
    if portal:
        names[5]='_ZNK9CMMUPKeys12GetKeyStringERK9CMMStringS2_RS0_i'
        names[6]='_ZN9CMMUPKeys12AddKeyStringERK9CMMStringS2_S2_i'
        names.append('_ZNK9CMMString9GetBufferE28t_cmmstring_characterSetTypeP28t_cmmstring_ConversionStatus')
    profiles = []
    for variant in ('NAV', 'AUDIO_BT_256'):
        symbols = ROOT/'artifacts/phase2/filesystems'/variant/'system/Application/PKG/abs_symbols_base.txt.gz'
        text = gzip.decompress(symbols.read_bytes()).decode('latin1')
        lookup = {x.split()[2]: int(x.split()[0],16) for x in text.splitlines() if len(x.split())==3}
        image = (ROOT/'artifacts/phase2/applications'/variant/'app.bin').read_bytes()
        profile = []
        for name in names:
            address = lookup[name]; raw = image[address-0x1000000:address-0x1000000+64]
            if len(raw)!=64: raise ValueError('Short API fingerprint')
            h = 2166136261
            for b in raw: h = ((h ^ b)*16777619)&0xffffffff
            profile.append((address,h))
        profiles.append(profile)
    rows = ['    {%s, %s, 64, %s, %s},' % tuple(hex(x)+'u' for x in (n[0],a[0],n[1],a[1]))
            for n,a in zip(*profiles)]
    (ROOT/'artifacts/phase8/usb-maintenance'/('usb_portal_api_fingerprints.h' if portal else 'usb_up_api_fingerprints.h')).write_text(
        'struct ApiCheck {unsigned int nav_address,audio_address,bytes,nav_hash,audio_hash;};\n'
        'static const struct ApiCheck api_checks[] = {\n'+'\n'.join(rows)+'\n};\n')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--sandbox-set-web', action='store_true',
                   help='Experimental virtual-image writer; backs up then calls native one-key API. Not approved for physical use.')
    p.add_argument('--runtime-gates',action='store_true',help='QEMU-only guarded RAM instruction experiment; no DB or firmware-file writes')
    p.add_argument('--runtime-set-web',action='store_true',help='QEMU-only backup, guarded RAM gates, then native one-key Web save')
    p.add_argument('--sandbox-set-portal',action='store_true',help='QEMU-only native portal URL save; diagnostic HTML remains on virtual USB')
    p.add_argument('--sandbox-restore-portal',action='store_true',help='QEMU-only restore of the exact prior portal URL after backup')
    p.add_argument('--network-cache',choices=['config','bluetooth','agenda','desktop','browser','menu','presence','early'],help='QEMU-only native RAM configuration-cache experiment')
    p.add_argument('--network-enable-web',action='store_true',help='With --network-cache, request only the existing Web_active key after full backup')
    p.add_argument('--network-keep-agenda',action='store_true',help='Preserve the original agenda force_no_dun field in network experiments')
    p.add_argument('--network-async',action='store_true',help='Only with the early emulator probe: return from entry while a bounded native task observes startup')
    p.add_argument('--network-bootstrap',action='store_true',help='Only with early+async: emulator-only guarded InitializeMetaAudioBt handoff')
    a = p.parse_args()
    output = a.output.resolve()
    if not any(output.is_relative_to(ROOT/'artifacts'/phase) for phase in ('phase8','phase11','phase12')) or output.exists():
        p.error('New image inside artifacts/phase8 or phase11 required; physical media is unsupported')
    output.parent.mkdir(parents=True, exist_ok=True)
    if sum([a.runtime_gates,a.sandbox_set_web,a.runtime_set_web,a.sandbox_set_portal,a.sandbox_restore_portal,bool(a.network_cache)])>1:p.error('Choose one experiment')
    if a.network_enable_web and not a.network_cache:p.error('--network-enable-web requires --network-cache')
    if a.network_keep_agenda and not a.network_cache:p.error('--network-keep-agenda requires --network-cache')
    if a.network_cache=='early' and a.network_enable_web:p.error('Early probe requires an already-prepared Web seed; it never calls UP setters during startup')
    if a.network_async and a.network_cache!='early':p.error('--network-async requires --network-cache early')
    if a.network_bootstrap and not(a.network_async and a.network_cache=='early'):p.error('Bootstrap requires early+async')
    if a.sandbox_set_portal or a.sandbox_restore_portal:write_api_checks(portal=True)
    if a.sandbox_set_web or a.runtime_set_web or a.network_enable_web: write_api_checks()
    if a.network_cache:
        checks=[]
        app=(ROOT/'artifacts/phase2/applications/AUDIO_BT_256/app.bin').read_bytes()
        addresses=[0x112a904,0x112bbf0,0x112a994,0x112abe4,0x11334e8,0x1958d74,0x27bde48,0x27b2b10,0x182d230,0x182d120,0x182d3f8]
        segment2=(ROOT/'artifacts/phase2/applications/AUDIO_BT_256/app_segment2.bin').read_bytes()
        if a.network_cache in ('browser','menu','presence'):addresses += [0x278a95c,0x4c9b564,0x4c86cec,0x4c170c0]
        if a.network_cache in ('menu','presence'):addresses += [0x4c90b10]
        if a.network_cache=='presence':addresses += [0x4c863ac,0x260480c,0x1505624]
        if a.network_cache=='early':addresses=[0x112bbf0,0x112a994,0x112abe4,0x11334e8,0x1958d74,0x1021848,0x1022924,0x10f21c0,0x10f1dcc,0x10f557c,0x10f1ce0,0x10f1cf0]
        if a.network_bootstrap:addresses += [0x1000000]
        for address in addresses:
            image,load=(segment2,0x4c00000) if address>=0x4c00000 else (app,0x1000000)
            raw=image[address-load:address-load+64];assert len(raw)==64
            h=2166136261
            for b in raw:h=((h^b)*16777619)&0xffffffff
            checks.append('    {%su,64,%su},'%(hex(address),hex(h)))
        (output.parent/'usb_network_api_checks.h').write_text('struct NetworkCheck {unsigned int address,length,hash;};\nstatic const struct NetworkCheck network_checks[]={\n'+'\n'.join(checks)+'\n};\n')
    if a.runtime_gates or a.runtime_set_web:
        guards=[]
        for filename,base,address in [('app.bin',0x1000000,0x227f46c),('app_segment2.bin',0x4c00000,0x4c170c0)]:
            with (ROOT/'artifacts/phase2/applications/AUDIO_BT_256'/filename).open('rb')as f:
                f.seek(address-base);raw=f.read(64)
            h=2166136261
            for b in raw:h=((h^b)*16777619)&0xffffffff
            guards.append('    {%su,64,%su},'%(hex(address),hex(h)))
        (output.parent/'usb_runtime_fingerprints.h').write_text(
            'struct Guard {unsigned int address,length,hash;};\nstatic const struct Guard guards[]={\n'+'\n'.join(guards)+'\n};\n')
    basename = 'sandbox_restore_portal' if a.sandbox_restore_portal else 'sandbox_set_portal' if a.sandbox_set_portal else 'runtime_and_web' if a.runtime_set_web else 'runtime_gates' if a.runtime_gates else ('sandbox_set_web' if a.sandbox_set_web else 'readonly_backup')
    if a.network_cache:basename='network_cache_'+a.network_cache
    if a.network_async:basename+='_async'
    if a.network_bootstrap:basename+='_bootstrap'
    module = output.parent/(basename+'.out')
    source = 'usb_runtime_gates.c' if a.runtime_gates else ('usb_set_web_sandbox.c' if a.sandbox_set_web else 'usb_backup_readonly.c')
    if a.sandbox_set_portal or a.sandbox_restore_portal:source='usb_set_portal_sandbox.c'
    if a.network_cache:source='usb_network_cache_sandbox.c'
    if a.network_cache=='early':source='usb_network_early_sandbox.c'
    if a.runtime_set_web:
        wrapper=output.parent/'runtime_and_web.c'
        wrapper.write_text('#define SMEG_RUNTIME_AND_WEB 1\n#include "usb_set_web_sandbox.c"\n#include "usb_runtime_gates.c"\n')
        source=wrapper
    subprocess.run(['clang','--target=powerpc-unknown-linux-gnu','-mbig-endian','-m32',
                    '-mlongcall','-ffreestanding','-fno-pic','-fno-stack-protector',
                    '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-msoft-float',
                    '-I',str(ROOT/'artifacts/phase8/usb-maintenance'),
                    '-I',str(output.parent),
                    '-I',str(ROOT/'emulation'),
                    *(['-DSMEG_RESTORE_STOCK_PORTAL=1'] if a.sandbox_restore_portal else []),
                    *(['-DSMEG_NETWORK_STAGE='+str(['config','bluetooth','agenda','desktop','browser','menu','presence','early'].index(a.network_cache)+1)] if a.network_cache else []),
                    *(['-DSMEG_NETWORK_ENABLE_WEB=1'] if a.network_enable_web else []),
                    *(['-DSMEG_NETWORK_KEEP_AGENDA=1'] if a.network_keep_agenda else []),
                    *(['-DSMEG_EARLY_ASYNC=1'] if a.network_async else []),
                    *(['-DSMEG_EARLY_BOOTSTRAP=1'] if a.network_bootstrap else []),
                    '-O2','-c',str(ROOT/'emulation'/source),'-o',str(module)],check=True)
    payload = module.read_bytes()
    if payload[:6] != b'\x7fELF\x01\x02': raise ValueError('Expected PPC32 big-endian ELF')
    # As in the previously executed native marker, the loader consumes the
    # relocatable text entry. No branch, checksum check, or loader is patched.
    body = (f'{crc16(payload):04x}\r\nVER:SMEG5.43.A.R2\r\nTYPE:RELOCABLE\r\nID:0\r\n'
            f'COMPRESSED:NO\r\nSIZE:{len(payload)}\r\nENTRY:YES\r\n').encode()
    files = {'FLYING/'+basename+'.out':payload,
             'FLYING/'+basename+'.out.inf':f'{crc16(body):04x}'.encode()+body}
    body = ('0000\r\nACTION:TemporaryBootRom\r\nLOAD_AND_EXECUTE:/bd0/FLYING/'+basename+'.out\r\n').encode()
    files['FLYING/doctor_smeg_plus_i.inf'] = f'{crc16(body):04x}'.encode()+body
    if a.sandbox_set_portal:
        files['SMEG_CAP/index.html']=(b'<!DOCTYPE html><html><head><meta charset="utf-8"><title>USB capability probe</title>'
            b'<style>body{margin:0;background:#102337;color:white;font:24px Arial}main{margin:65px 105px}button{font:26px Arial;padding:20px}</style></head>'
            b'<body><main><h1>USB page loaded</h1><p id="state">JavaScript not run</p>'
            b'<button onclick="n++;document.getElementById(\'state\').innerHTML=\'Touch acknowledged: \'+n">Test native touch</button>'
            b'<p>Diagnostic only. No vehicle controls.</p></main><script>var n=0;document.getElementById("state").innerHTML="JavaScript running from USB";</script></body></html>')
    def run(*args):
        return subprocess.run(args,check=True,capture_output=True,
                              env=dict(os.environ,MTOOLS_SKIP_CHECK='1'))
    offset, size = 1048576, 128*1024*1024
    with tempfile.TemporaryDirectory(prefix='smeg-readonly-usb-') as tmp:
        tmp = Path(tmp)
        partition = tmp/'partition.fat'
        with partition.open('xb') as f: f.truncate(size)
        run('mkfs.vfat','-F','32','-n','QEMU_RO',str(partition))
        mbr = bytearray(512)
        mbr[446:462] = struct.pack('<B3sB3sII',0,b'\xfe\xff\xff',0x0c,b'\xfe\xff\xff',2048,size//512)
        mbr[510:512] = b'\x55\xaa'
        with output.open('xb') as f:
            f.write(mbr); f.seek(offset)
            with partition.open('rb') as src:
                while chunk := src.read(1024*1024): f.write(chunk)
        spec = str(output)+'@@'+str(offset)
        run('mmd','-i',spec,'::/FLYING')
        if a.sandbox_set_portal:run('mmd','-i',spec,'::/SMEG_CAP')
        for i,(name,data) in enumerate(files.items()):
            src = tmp/str(i); src.write_bytes(data)
            run('mcopy','-i',spec,str(src),'::/'+name)
            check = tmp/('readback'+str(i))
            run('mcopy','-i',spec,'::/'+name,str(check))
            assert check.read_bytes() == data
    result = {'emulator_only':True,'physical_car_approved':False,'physical_device_access':False,
              'module':('Experimental native network RAM cache stage='+a.network_cache+('; Web_active one-key request' if a.network_enable_web else '; no parameter save') if a.network_cache else
                        'Experimental native one-key stock portal restoration after backup' if a.sandbox_restore_portal else
                        'Experimental native one-key portal path save after backup; USB-hosted diagnostic page' if a.sandbox_set_portal else
                        'Experimental RAM gates followed by native single-key save after backup' if a.runtime_set_web else
                        'Experimental RAM-only instruction gates; no firmware-file or DB writes' if a.runtime_gates else
                        'Experimental native single-key writer after backup' if a.sandbox_set_web else
                        'Experimental read-only native backup; all source fopen modes rb'),
              'checksum_is_not_vendor_signature':True,
              'files':[{'path':n,'sha256':hashlib.sha256(v).hexdigest()} for n,v in files.items()]}
    output.with_suffix('.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'image':str(output),'module_bytes':len(payload),'emulator_only':True}))


if __name__ == '__main__': main()
