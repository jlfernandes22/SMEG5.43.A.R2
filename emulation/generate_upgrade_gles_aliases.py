#!/usr/bin/env python3
"""Map the original updater's GLES exports onto existing tested host GL handlers."""
from pathlib import Path
import hashlib
import json
import re
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
root=Path(__file__).resolve().parent.parent
source=root/'artifacts/phase2/package/SMEG_PLUS_UPG/upgrade.out'
metadata=Path(__file__).with_name('smeg_gles_symbols.inc').read_text()
exports=re.findall(r'\{0x[0-9a-f]+, "([^"]+)", "[^"]+"\}',metadata)
rows=[]
with source.open('rb') as stream:
 elf=ELFFile(stream);sym=elf.get_section_by_name('.symtab')
 for symbol in sym.iter_symbols():
  if symbol.name not in exports or symbol['st_info']['type']!='STT_FUNC' or not isinstance(symbol['st_shndx'],int):continue
  off=symbol['st_value'];section=elf.get_section(symbol['st_shndx']);code=section.data()[off:off+16];mask=bytearray(b'\xff'*16)
  if len(code)!=16:raise ValueError('Short function signature')
  for sec in elf.iter_sections():
   if not isinstance(sec,RelocationSection) or sec['sh_info']!=symbol['st_shndx']:continue
   for relocation in sec.iter_relocations():
    start=relocation['r_offset']
    # Conservatively ignore the entire relocated instruction in the signature.
    if off<=start<off+16:
     start=(start-off)&~3;mask[start:start+4]=b'\0'*4
  if not any(mask):raise ValueError('No fixed signature bytes')
  words=lambda b:','.join(f'0x{int.from_bytes(b[i:i+4],"big"):08x}'for i in range(0,16,4))
  rows.append((off,f'{{0x{off:08x}, {exports.index(symbol.name)}, {{{words(code)}}}, {{{words(mask)}}}}}, /* {symbol.name} */'))
rows.sort()
Path(__file__).with_name('smeg_gles_upgrade_aliases.inc').write_text('/* Original upgrade.out offsets and masked instruction signatures. */\n'+'\n'.join(line for _,line in rows)+'\n')
(root/'artifacts/phase5/update/upgrade-gles-aliases.json').write_text(json.dumps({'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'alias_count':len(rows),'signatures_mask_relocations':True,'requires_observed_load_base':True},indent=2)+'\n')
print('Generated',len(rows),'verified updater GLES aliases')
