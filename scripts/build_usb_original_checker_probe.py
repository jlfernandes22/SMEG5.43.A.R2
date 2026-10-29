#!/usr/bin/env python3
"""Extract ONLY the original file verifier's instructions, then wrap read-only."""
import argparse,hashlib,json,os,shutil,subprocess,tempfile,zlib
from pathlib import Path
from elftools.elf.elffile import ELFFile
from smeg_db_inf import crc16
from build_usb_resource_probe import fnv
ROOT=Path(__file__).resolve().parents[1]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();assert out.is_relative_to(ROOT/'artifacts/phase21')and not out.exists();out.mkdir(parents=True)
 original=ROOT/'artifacts/phase20/complete-stock-probe-v7/theme_resources.out'
 with original.open('rb')as f:
  elf=ELFFile(f);syms=elf.get_section_by_name('.symtab');sym=next(s for s in syms.iter_symbols()if s.name=='check_source');lo,size=sym['st_value'],sym['st_size'];code=elf.get_section_by_name('.text').data()[lo:lo+size];data=elf.get_section_by_name('.data.rel.ro').data();table=next(s for s in syms.iter_symbols()if s.name=='resource_crc_table');assert table['st_size']==1024
  mappings={4:'R_PPC_ADDR16_LO',6:'R_PPC_ADDR16_HA'};relocs=[]
  for r in elf.get_section_by_name('.rela.text').iter_relocations():
   if lo<=r['r_offset']<lo+size:
    symbol=syms.get_symbol(r['r_info_sym']);name=symbol.name
    if symbol['st_shndx']=='SHN_UNDEF':assert name in {'fopen','fread','ferror','fclose'}
    else:
     section=elf.get_section(symbol['st_shndx']).name;name={'.data.rel.ro':'original_context_data','.bss':'original_source_buffer'}[section]
    assert r['r_info_type']in mappings;relocs.append(dict(offset=r['r_offset']-lo,kind=mappings[r['r_info_type']],symbol=name,addend=r['r_addend']))
 (out/'original-checker.bin').write_bytes(code);(out/'original-constants.bin').write_bytes(data)
 assembly=['.section .text,"ax",@progbits','.balign 4','.globl original_check_source','.type original_check_source,@function','original_check_source:',f'.incbin "{out}/original-checker.bin"',f'.size original_check_source,{size}']
 assembly += [f'.reloc original_check_source+{r["offset"]},{r["kind"]},{r["symbol"]}+{r["addend"]}'for r in relocs]
 assembly += ['.section .bss,"aw",@nobits','.balign 64','.zero 4','.globl original_source_buffer','original_source_buffer:','.zero 1024','.globl original_source_guard','original_source_guard:','.zero 8192','.section .data.rel.ro.original,"aw",@progbits','.balign 4','.globl original_context_data','original_context_data:',f'.incbin "{out}/original-constants.bin"']
 (out/'original-checker.S').write_text('\n'.join(assembly)+'\n');bank=(ROOT/'artifacts/phase20/complete-stock-probe-v7/bank1.bin').read_bytes()
 (out/'original_checker_contract.h').write_text(f'#define ORIGINAL_DATA_BYTES {len(data)}u\n#define ORIGINAL_DATA_FNV 0x{fnv(data):08x}u\n#define ORIGINAL_CRC_TABLE_OFFSET {table["st_value"]}u\n#define SOURCE_PATH "/bd0/THEME_TEST/bank1.bin"\n#define SOURCE_BYTES {len(bank)}u\n#define SOURCE_CRC 0x{zlib.crc32(bank):08x}u\n#define SOURCE_FNV 0x{fnv(bank):08x}u\n')
 common=['clang','--target=powerpc-unknown-linux-gnu','-mbig-endian','-m32','-mlongcall','-ffreestanding','-fno-pic','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-msoft-float','-I',str(out),'-O2','-Wall','-Wextra','-Werror','-c']
 subprocess.run(common+[str(ROOT/'emulation/usb_original_checker_probe.c'),'-o',str(out/'wrapper.o')],check=True);subprocess.run(['clang','--target=powerpc-unknown-linux-gnu','-c',str(out/'original-checker.S'),'-o',str(out/'checker.o')],check=True)
 module=out/'checksrc.out';subprocess.run(['ld.lld','-r','-m','elf32ppc',str(out/'wrapper.o'),str(out/'checker.o'),'-o',str(module)],check=True)
 with module.open('rb')as f:
  e=ELFFile(f);s=e.get_section_by_name('.symtab');entry=next(v for v in s.iter_symbols()if v.name=='smeg_original_checker_probe');checker=next(v for v in s.iter_symbols()if v.name=='original_check_source');assert entry['st_value']==0;actual=e.get_section_by_name('.text').data()[checker['st_value']:checker['st_value']+size];assert actual==code
 image=out/'usb.raw';shutil.copyfile(ROOT/'artifacts/phase21/read-only-source-diagnostic-v1/usb.raw',image);spec=str(image)+'@@1048576';env=dict(os.environ,MTOOLS_SKIP_CHECK='1')
 def run(*c):return subprocess.run(c,check=True,capture_output=True,env=env)
 run('mdeltree','-i',spec,'::/FLYING');run('mmd','-i',spec,'::/FLYING');raw=module.read_bytes();body=(f'{crc16(raw):04x}\r\nVER:SMEG5.43.A.R2\r\nTYPE:RELOCABLE\r\nID:0\r\nCOMPRESSED:NO\r\nSIZE:{len(raw)}\r\nENTRY:YES\r\n').encode();doctor=b'0000\r\nACTION:TemporaryBootRom\r\nLOAD_AND_EXECUTE:/bd0/FLYING/checksrc.out\r\n'
 files={'FLYING/checksrc.out':raw,'FLYING/checksrc.out.inf':f'{crc16(body):04x}'.encode()+body,'FLYING/doctor_smeg_plus_i.inf':f'{crc16(doctor):04x}'.encode()+doctor}
 with tempfile.TemporaryDirectory()as td:
  for i,(n,d)in enumerate(files.items()):
   q=Path(td)/str(i);q.write_bytes(d);run('mcopy','-i',spec,str(q),'::/'+n);assert run('mtype','-i',spec,'::/'+n).stdout==d
 meta=dict(scope='Read-only exact original verifier test, native header reads and buffer comparison',image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),original_module_sha256=hashlib.sha256(original.read_bytes()).hexdigest(),extracted_code_sha256=hashlib.sha256(code).hexdigest(),extracted_code_bytes=size,extracted_original_checker_instructions_byte_exact=True,legacy_buffer_forced_mod64=4,extracted_function_only_stdio_calls=True,excluded_all_original_installer_code_except_checker=True,relocations=relocs,source_sha256=hashlib.sha256((ROOT/'emulation/usb_original_checker_probe.c').read_bytes()).hexdigest(),NAND_write_APIs=False,configuration_setters=False,automatic_reboot=False,module_imports=subprocess.check_output(['llvm-nm','-u',str(module)],text=True))
 (out/'usb.json').write_text(json.dumps(meta,indent=2)+'\n');print(image)
if __name__=='__main__':main()
