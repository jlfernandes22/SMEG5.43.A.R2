#!/usr/bin/env python3
"""Read-only proof of BigQuick bytes and BSP legacy-BBT address correction."""
import argparse, hashlib, json, struct, zlib
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--image',type=Path,required=True)
p.add_argument('--container',type=Path,default=Path('artifacts/phase2/package/SMEG_PLUS_UPG/NAV/AppBin/f_BigQuick.bin'))
p.add_argument('--output',type=Path,required=True)
a=p.parse_args(); source=a.container.read_bytes(); area=0x14a0000
with a.image.open('rb') as f:
 def read(offset,length):
  out=bytearray()
  while length:
   page,col=divmod(offset,2048);n=min(2048-col,length);f.seek(page*2112+col);v=f.read(n)
   if len(v)!=n:raise ValueError('NAND read outside image')
   out.extend(v);offset+=n;length-=n
  return bytes(out)
 actual=read(area,len(source)); report={'scope':'Read-only offline byte audit; no guest calls or media writes','image':str(a.image),'source':str(a.container),'full_container_sha256':hashlib.sha256(actual).hexdigest(),'original_sha256':hashlib.sha256(source).hexdigest(),'full_container_matches':actual==source,'segments':[],'legacy_bbt_capacity_cases':[]}
 for i,offset in enumerate([0x800,(struct.unpack_from('>I',source,32)[0]+1)*2048]):
  d=zlib.decompressobj();raw=d.decompress(actual[offset+1:])+d.flush();expected=struct.unpack_from('>I',source,i*32+4)[0]
  report['segments'].append({'index':i,'container_offset':hex(offset),'nand_offset':hex(area+offset),'compression_marker':actual[offset],'zlib_complete':d.eof,'inflated_bytes':len(raw),'expected_bytes':expected,'inflated_size_matches':len(raw)==expected,'inflated_sha256':hashlib.sha256(raw).hexdigest()})
 offset=(struct.unpack_from('>I',source,32)[0]+1)*2048
 for capacity in [0x10000000,0x20000000]:
  page=0x1ffc0 if capacity==0x10000000 else 0x3ff80;size=0x200 if capacity==0x10000000 else 0x400;bbt=read(page*2048,2048);bad=[]
  # Exact native GetBbtTable inclusive loop and 2-bit zero=bad encoding.
  for i,x in enumerate(bbt[:size+1]):
   for j in range(4):
    if ((x>>(2*j))&3)==0:bad.append(i*0x80000+j*0x20000)
  aligned=area+((offset>>17)<<17);skip=0
  for block in bad:
   if area<=block<=aligned+skip:skip+=0x20000
  target=area+offset+skip;head=read(target,32)
  report['legacy_bbt_capacity_cases'].append({'BSP_capacity':hex(capacity),'BBT_page':hex(page),'BBT_head':bbt[:64].hex(),'bad_blocks':len(bad),'second_segment_skip':hex(skip),'second_segment_target':hex(target),'physical_page':target//2048,'target_head':head.hex(),'matches_original_second_segment':head==source[offset:offset+32]})
a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'full_container_matches':report['full_container_matches'],'segments':[v['inflated_size_matches']for v in report['segments']],'BBTcases':report['legacy_bbt_capacity_cases']},indent=2))
