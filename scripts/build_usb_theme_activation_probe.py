#!/usr/bin/env python3
"""Sandbox-only USB: six stock previews plus six theme-only native flags."""
import hashlib
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from prepare_all_theme_assets import previews
from smeg_db_inf import crc16
from build_usb_resource_probe import fnv

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT/'artifacts/phase20/theme-activation-probe'
OLD = ROOT/'artifacts/phase19/extra-theme-flags/usb-probe'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    global OUT
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=OUT)
    args=parser.parse_args()
    OUT=args.output.resolve()
    assert OUT.is_relative_to(ROOT/'artifacts/phase20')
    assert not OUT.exists()
    OUT.mkdir(parents=True)
    old = json.loads((OLD/'usb.json').read_text())
    assert sha((OLD/'usb.raw').read_bytes()) == old['image_sha256']
    shutil.copyfile(OLD/'usb_warmlight_api_fingerprints.h',OUT/'usb_warmlight_api_fingerprints.h')
    contracts, files = [], {}
    for group, uid in [(1,1),(1,2),(1,3),(2,4),(2,7),(2,8)]:
        _, data = previews(group, 'AUDIO')[uid]
        directory=f'/SYSTEM/Data_Base/BOARDFS/GUI_STYLE/GUIS_RESSOURCES/Harmony{uid}'
        source=f'/bd0/PREVIEWS/theme{uid}.jpg'
        contracts.append('{"%s","%s","%s",%du,0x%xu},' %
                         (source,directory,directory+'/skin.jpg',len(data),fnv(data)))
        files[f'PREVIEWS/theme{uid}.jpg']=data
    (OUT/'theme_preview_contract.h').write_text(
        'struct ThemePreview {const char *source,*directory,*destination; unsigned bytes,hash;};\n'
        'static const struct ThemePreview theme_previews[] = {\n'+'\n'.join(contracts)+'\n};\n')
    bsp=(ROOT/'artifacts/phase2/package/SMEG_PLUS_UPG/BSP/SMEG_PLUS_256/vxWorks.bin').read_bytes()
    fs_checks=[dict(symbol=n,address=address,hash=fnv(bsp[address-0x200000:address-0x200000+64]))
               for n,address in [('dosFsVolDescGet',0x468440),('dosFsVolumeReadOnlySet',0x46e4d4)]]
    (OUT/'theme_preview_fs_contract.h').write_text('struct PreviewFSAPI {unsigned address,hash;};\n'
        'static const struct PreviewFSAPI preview_fs_api[] = {\n' +
        '\n'.join('{0x%xu,0x%xu},'%(r['address'],r['hash'])for r in fs_checks)+'\n};\n')
    source=ROOT/'emulation/usb_theme_previews_sandbox.c'
    module=OUT/'extra_theme_flags.out'
    command=['clang','--target=powerpc-unknown-linux-gnu','-mbig-endian','-m32','-mlongcall',
             '-ffreestanding','-fno-pic','-fno-stack-protector','-fno-unwind-tables',
             '-fno-asynchronous-unwind-tables','-msoft-float','-I',str(OUT),'-I',str(ROOT/'emulation'),
             '-O2','-Wall','-Wextra','-Werror','-c',str(source),'-o',str(module)]
    subprocess.run(command,check=True)
    payload=module.read_bytes()
    body=(f'{crc16(payload):04x}\r\nVER:SMEG5.43.A.R2\r\nTYPE:RELOCABLE\r\nID:0\r\n'
          f'COMPRESSED:NO\r\nSIZE:{len(payload)}\r\nENTRY:YES\r\n').encode()
    files['FLYING/extra_theme_flags.out']=payload
    files['FLYING/extra_theme_flags.out.inf']=f'{crc16(body):04x}'.encode()+body
    # Retain the already tested doctor entry and original fingerprint contract.
    image=OUT/'usb.raw'
    subprocess.run(['cp','--reflink=auto',str(OLD/'usb.raw'),str(image)],check=True)
    spec=str(image)+'@@1048576';env=dict(os.environ,MTOOLS_SKIP_CHECK='1')
    def run(*cmd):
        return subprocess.run(cmd,check=True,capture_output=True,env=env)
    run('mmd','-i',spec,'::/PREVIEWS')
    with tempfile.TemporaryDirectory()as td:
        for index,(name,data)in enumerate(files.items()):
            path=Path(td)/str(index);check=Path(td)/('check'+str(index))
            path.write_bytes(data)
            run('mcopy','-o','-i',spec,str(path),'::/'+name)
            run('mcopy','-i',spec,'::/'+name,str(check))
            assert check.read_bytes()==data
    metadata=dict(emulator_only=True,physical_car_approved=False,physical_device_access=False,
                  image=str(image),image_sha256=sha(image.read_bytes()),
                  requested_flags=old['native_request'],replacement_databases=False,
                  selected_theme_changed_by_helper=False,firmware_or_binary_patches=False,
                  native_temporary_SYSTEM_mount_mode='Read prior flag; temporarily set writable via guarded dosFsVolumeReadOnlySet; restore prior flag on cleanup',
                  filesystem_API_fingerprints=fs_checks,
                  new_preview_files=[n for n in files if n.startswith('PREVIEWS/')],
                  sources=[dict(path=str(p),sha256=sha(p.read_bytes()))for p in
                           [source,ROOT/'emulation/usb_extra_theme_flags_sandbox.c',ROOT/'emulation/usb_backup_readonly.c']],
                  files=[dict(path=n,bytes=len(d),sha256=sha(d))for n,d in files.items()],
                  compile_command=command)
    (OUT/'usb.json').write_text(json.dumps(metadata,indent=2)+'\n')
    print(json.dumps({'image':str(image),'new_previews':metadata['new_preview_files'],
                      'requested_flags':metadata['requested_flags'],'emulator_only':True},indent=2))


if __name__=='__main__':
    main()
