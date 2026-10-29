#!/usr/bin/env python3
"""Create a regular FAT32 USB-image file for a native-updater QEMU test."""
import argparse
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]


def create(package,image):
    package,image=Path(package).resolve(),Path(image).resolve()
    assert package.is_dir() and package.name=='SMEG_PLUS_UPG'
    assert package.is_relative_to(ROOT/'artifacts') and image.is_relative_to(ROOT/'artifacts/phase13')
    assert not image.exists()
    image.parent.mkdir(parents=True,exist_ok=True)
    size,first=2*1024**3,2048;sectors=size//512-first
    mbr=bytearray(512);mbr[446:462]=struct.pack('<B3sB3sII',0,b'\xfe\xff\xff',0x0c,b'\xfe\xff\xff',first,sectors);mbr[510:]=b'\x55\xaa'
    with image.open('xb')as f:f.truncate(size);f.write(mbr)
    subprocess.run(['mkfs.vfat','-F','32','-n','SMEG_TEST','--offset',str(first),str(image),str(sectors//2)],check=True,capture_output=True)
    subprocess.run(['mcopy','-s','-i',str(image)+'@@1048576',str(package),'::/'],check=True,capture_output=True,env=dict(os.environ,MTOOLS_SKIP_CHECK='1'))
    result={'emulator_only':True,'physical_car_approved':False,'package':str(package),'virtual_USB':str(image),'bytes':size,'partition_offset':1048576,'FLYING_loader_used':False}
    if (package/'NAV/USER_DATA/user_data/sqlite').is_dir():
        # Native xcopy uses readdir names, and this VxWorks version ignores
        # the DOS short-name lowercase flag. It requires a literal lowercase
        # sqlite LFN; ordinary mcopy can silently omit that record.
        report=image.with_suffix('.lfn.json')
        subprocess.run([sys.executable,str(ROOT/'scripts/ensure_smeg_fat_lfn.py'),
                        '--image',str(image),'--apply','--report',str(report)],
                       check=True,capture_output=True)
        result['native_sqlite_LFN_report']=str(report)
    image.with_suffix('.json').write_text(json.dumps(result,indent=2)+'\n');return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--package',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    print(json.dumps(create(a.package,a.output)))
