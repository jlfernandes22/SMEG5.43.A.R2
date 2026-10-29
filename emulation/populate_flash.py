#!/usr/bin/env python3
"""Build an offline populated copy of native-formatted NAND, preserving FlashFX.

The input must be closed by QEMU. Native BBM/VBF unit headers are discovered by
inject_volume.py; this script never writes tar bytes at guessed NAND offsets.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--input',type=Path,required=True)
p.add_argument('--output',type=Path,default=Path('artifacts/phase3/nand-populated.raw'))
p.add_argument('--work',type=Path,default=Path('artifacts/phase3/populate'))
a=p.parse_args()
if a.output.exists() or a.work.exists():
    raise SystemExit('Output/work directory must be new; existing images are preserved')
a.work.mkdir(parents=True)
def run(script,*args):
    subprocess.run([sys.executable,'emulation/'+script,*map(str,args)],check=True)
run('prepare_payloads.py')
reserved=a.work/'reserved.raw'
run('seed_harmony.py','--input',a.input,'--output',reserved)
run('inject_reserved.py','--image',reserved)
# Native start-page positions are derived from the 0x2cd00-KiB reserved bottom
# and the original disk-create boundaries, then validated by actual VBF/FAT.
volumes=[('SYSTEM_DATA',91776),('SYSTEM',92992),
         ('SYSTEM_TMP_DATA',149760),('USER_DATA',220032)]
current=reserved
for index,(name,base) in enumerate(volumes):
    dest=a.output if index==len(volumes)-1 else a.work/(name+'.raw')
    run('inject_volume.py','--input',current,'--output',dest,
        '--base-page',base,'--source',Path('artifacts/phase3/payloads')/name)
    current=dest
print(json.dumps({'output':str(current),'populated_volumes':[v[0] for v in volumes],
                  'physical_data_capacity_mib':512,'page_data_bytes':2048,
                  'page_oob_bytes':64,'pages_per_erase_block':64,
                  'raw_application_offset':'0x014a0000',
                  'native_reboot_validation':'required'}))
