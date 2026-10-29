#!/usr/bin/env python3
"""Build the exact shared verifier/UI test with no persistent car writer code."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from elftools.elf.elffile import ELFFile
from smeg_db_inf import crc16
from theme_progress_contract import write_contract
ROOT=Path(__file__).resolve().parents[1]
def sha(p):
    with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();out=a.output.resolve()
    assert out.is_relative_to(ROOT/'artifacts/phase21') and not out.exists()
    out.mkdir(parents=True)
    template=ROOT/'artifacts/phase21/original-checker-readonly-v3/usb.raw'
    resources=ROOT/'artifacts/phase20/complete-stock-retry-v8'
    shutil.copyfile(resources/'theme_resource_contract.h',out/'theme_resource_contract.h')
    progress=write_contract(ROOT,out)
    for name in ['usb_theme_retry_readonly.c','theme_source_verify.h','theme_install_progress.h']:
        shutil.copyfile(ROOT/'emulation'/name,out/name)
    module=out/'readcheck.out';source=out/'usb_theme_retry_readonly.c'
    command=['clang','--target=powerpc-unknown-linux-gnu','-mbig-endian','-m32','-mlongcall','-ffreestanding','-fno-pic',
        '-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-msoft-float','-O2','-Wall','-Wextra','-Werror',
        '-I',str(out),'-c',str(source),'-o',str(module)]
    subprocess.run(command,check=True)
    with module.open('rb')as f:
        elf=ELFFile(f);symbols=list(elf.get_section_by_name('.symtab').iter_symbols())
        entry=next(s for s in symbols if s.name=='smeg_theme_retry_readonly')
        assert entry['st_value']==0 and elf.get_section(entry['st_shndx']).name=='.text'
        imports=sorted(s.name for s in symbols if s.name and s['st_shndx']=='SHN_UNDEF')
        assert set(imports)<={'fopen','fread','fprintf','snprintf','fflush','fclose','ferror','errnoGet','taskDelay','sysClkRateGet'},imports
        assert not any(s.name in {'smeg_install_theme_resources','smeg_complete_theme_install','smeg_set_theme_catalogue'}for s in symbols)
    payload=module.read_bytes()
    body=(f'{crc16(payload):04x}\r\nVER:SMEG5.43.A.R2\r\nTYPE:RELOCABLE\r\nID:0\r\nCOMPRESSED:NO\r\nSIZE:{len(payload)}\r\nENTRY:YES\r\n').encode()
    doctor=b'0000\r\nACTION:TemporaryBootRom\r\nLOAD_AND_EXECUTE:/bd0/FLYING/readcheck.out\r\n'
    files={'FLYING/readcheck.out':payload,'FLYING/readcheck.out.inf':f'{crc16(body):04x}'.encode()+body,
        'FLYING/doctor_smeg_plus_i.inf':f'{crc16(doctor):04x}'.encode()+doctor}
    image=out/'usb.raw';shutil.copyfile(template,image);spec=str(image)+'@@1048576';env=dict(os.environ,MTOOLS_SKIP_CHECK='1')
    def run(*cmd):return subprocess.run(cmd,capture_output=True,check=True,env=env)
    run('mdel','-i',spec,'::/FLYING/checksrc.out','::/FLYING/checksrc.out.inf','::/FLYING/doctor_smeg_plus_i.inf')
    with tempfile.TemporaryDirectory()as td:
        for i,(name,data)in enumerate(files.items()):
            path=Path(td)/str(i);path.write_bytes(data);run('mcopy','-i',spec,str(path),'::/'+name)
            assert run('mtype','-i',spec,'::/'+name).stdout==data
    for n in ['READCHECK.TXT','THEME_STATUS.TXT','UI_TRACE.TXT']:
        assert subprocess.run(['mtype','-i',spec,'::/'+n],capture_output=True,env=env).returncode!=0
    source_hashes={n:sha(out/n)for n in ['usb_theme_retry_readonly.c','theme_source_verify.h','theme_install_progress.h','theme_progress_contract.h','theme_resource_contract.h']}
    report=dict(read_only_car_test=True,physical_device_access=False,physical_car_approved=False,
        persistence_setters_included=False,NAND_erase_or_program_included=False,application_or_BSP_replacement=False,
        temporary_stock_UI_only=True,determinate_progress=True,
        progress_measure='Actual source bytes processed across two required matching reads; retries extend the work budget;100 requires final successful checks',
        source_template=str(template),source_template_sha256=sha(template),image=str(image),image_sha256=sha(image),
        module_imports=imports,entry_offset=0,progress_contract=progress,source_sha256=source_hashes,compile_command=command,
        files=[dict(path=n,bytes=len(d),sha256=hashlib.sha256(d).hexdigest())for n,d in files.items()])
    (out/'usb.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(dict(image=str(image),module_imports=imports)))
if __name__=='__main__':main()
