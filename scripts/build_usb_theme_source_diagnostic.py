#!/usr/bin/env python3
"""Create a read-only source diagnostic; retain original banks, remove installer."""
import argparse,hashlib,json,os,shutil,struct,subprocess,tempfile,zlib
from pathlib import Path
from smeg_db_inf import crc16
from build_usb_resource_probe import fnv
ROOT=Path(__file__).resolve().parents[1]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();assert out.is_relative_to(ROOT/'artifacts/phase21')and not out.exists();out.mkdir(parents=True)
 seed=ROOT/'artifacts/phase20/complete-stock-probe-v7';image=out/'usb.raw';shutil.copyfile(seed/'usb.raw',image);spec=str(image)+'@@1048576';env=dict(os.environ,MTOOLS_SKIP_CHECK='1')
 def run(*c):return subprocess.run(c,check=True,capture_output=True,env=env)
 cases=[]
 for n in (1,2):
  data=(seed/f'bank{n}.bin').read_bytes();cases.extend([dict(path=path,bytes=len(data),crc=zlib.crc32(data),fnv=fnv(data),prefix_bitwise_CRC32=zlib.crc32(data[:65536]))for path in (f'/bd0/THEME_TEST/bank{n}.bin',f'/bd0/THEME_~1/BANK{n}.BIN')])
 table=[]
 for i in range(256):
  v=i
  for bit in range(8):v=(v>>1)^(0xedb88320 if v&1 else 0)
  table.append(v)
 h=['struct SourceCase{const char*path;unsigned bytes,crc,fnv;};','static const struct SourceCase source_cases[]={']
 h += ['{"%s",%du,0x%08xu,0x%08xu},'%(r['path'],r['bytes'],r['crc'],r['fnv'])for r in cases]
 h+=['};','static const unsigned source_crc_table[256]={'+','.join('0x%08xu'%v for v in table)+'};']
 (out/'theme_source_diagnostic_contract.h').write_text('\n'.join(h)+'\n')
 source=ROOT/'emulation/usb_theme_source_diagnostic.c';module=out/'readsrc.out';command=['clang','--target=powerpc-unknown-linux-gnu','-mbig-endian','-m32','-mlongcall','-ffreestanding','-fno-pic','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-msoft-float','-I',str(out),'-O2','-Wall','-Wextra','-Werror','-c',str(source),'-o',str(module)]
 subprocess.run(command,check=True);raw=module.read_bytes();body=(f'{crc16(raw):04x}\r\nVER:SMEG5.43.A.R2\r\nTYPE:RELOCABLE\r\nID:0\r\nCOMPRESSED:NO\r\nSIZE:{len(raw)}\r\nENTRY:YES\r\n').encode();doctor=b'0000\r\nACTION:TemporaryBootRom\r\nLOAD_AND_EXECUTE:/bd0/FLYING/readsrc.out\r\n'
 run('mdeltree','-i',spec,'::/FLYING');run('mmd','-i',spec,'::/FLYING')
 files={'FLYING/readsrc.out':raw,'FLYING/readsrc.out.inf':f'{crc16(body):04x}'.encode()+body,'FLYING/doctor_smeg_plus_i.inf':f'{crc16(doctor):04x}'.encode()+doctor}
 with tempfile.TemporaryDirectory()as td:
  for n,(name,data)in enumerate(files.items()):
   q=Path(td)/str(n);q.write_bytes(data);run('mcopy','-i',spec,str(q),'::/'+name);assert run('mtype','-i',spec,'::/'+name).stdout==data
 metadata=dict(scope='Car-side read-only file-source diagnostic; writes only USB_DIAG on USB',source_cases=cases,source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),compile_command=command,NAND_write_APIs=False,configuration_setters=False,automatic_reboot=False,old_installer_removed=True,module_imports=subprocess.check_output(['llvm-nm','-u',str(module)],text=True))
 (out/'usb.json').write_text(json.dumps(metadata,indent=2)+'\n');print(image)
if __name__=='__main__':main()
