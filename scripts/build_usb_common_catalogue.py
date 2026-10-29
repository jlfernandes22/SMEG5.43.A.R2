#!/usr/bin/env python3
"""Sandbox-only native registration of exactly 18 installed-theme fields."""
import argparse,hashlib,json,os,shutil,subprocess,tempfile
from pathlib import Path
from build_usb_resource_probe import fnv
from theme_resource_format import native_bank
from smeg_db_inf import crc16
ROOT=Path(__file__).resolve().parents[1]
def contract(out,banks):
 app=(ROOT/'artifacts/phase2/applications/AUDIO_BT_256/app.bin').read_bytes()
 bsp=(ROOT/'artifacts/phase2/package/SMEG_PLUS_UPG/BSP/SMEG_PLUS_256/vxWorks.bin').read_bytes()
 apis=[0x1120ef8,0x111fb38,0x111f17c,0x1021848,0x11119b0,0x1110a64,0x11124e0,0x1110648,0x1111f64,0x110f114,0x110f374,0x1022924,0x101f8b8]
 bsps=[0x25f068,0x25f554]
 h=['struct CommonAPI{unsigned address,hash;};','static const struct CommonAPI common_api[]={'+','.join('{0x%xu,0x%xu}'%(v,fnv(app[v-0x1000000:v-0x1000000+64]))for v in apis)+'};',
    'static const struct CommonAPI common_bsp[]={'+','.join('{0x%xu,0x%xu}'%(v,fnv(bsp[v-0x200000:v-0x200000+64]))for v in bsps)+'};',
    'struct CatalogueBank{unsigned pre_hash,entries[4];};','static const struct CatalogueBank catalogue_banks[]={']
 for n in (1,2):
  p=banks/f'bank{n}.bin';raw=native_bank(p.read_bytes(),Path(str(p)+'.inf').read_bytes())
  h.append('{0x%xu,{%s}},'%(fnv(raw[:168]),','.join('0x%xu'%fnv(raw[2084+i*216:2084+(i+1)*216])for i in range(4))))
 h+=['};','struct CommonRow{const char*name,*string;int integer;};','static const struct CommonRow common_rows[]={']
 rows=[]
 for uid,name,number,code in [(1,'GRAPHIC',1,102),(2,'ELLIPTIC',1,202),(3,'CUBIC',2,203),(4,'REFLEX',3,204),(7,'ESSENTIEL',3,104),(8,'REDLINE',2,103)]:
  h += [f'{{"harmony{uid}","{name}",0}},',f'{{"harm{uid}_number",0,{number}}},',f'{{"harm{uid}_offset_area",0,{code}}},']
  rows += [dict(Section='supervisor',Name=f'harmony{uid}',Idx=0,StringValue=name),dict(Section='supervisor',Name=f'harm{uid}_number',Idx=0,IntValue=number),dict(Section='supervisor',Name=f'harm{uid}_offset_area',Idx=0,IntValue=code)]
 h+=['};'];(out/'theme_common_catalogue_contract.h').write_text('\n'.join(h)+'\n');return rows
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--banks',type=Path,default=ROOT/'artifacts/phase20/complete-stock-probe-v5');a=p.parse_args();out=a.output.resolve()
 assert out.is_relative_to(ROOT/'artifacts/phase20')and not out.exists();out.mkdir();rows=contract(out,a.banks.resolve())
 image=out/'usb.raw';shutil.copyfile(ROOT/'artifacts/phase11/usb-capabilities/read-only/usb.raw',image);spec=str(image)+'@@1048576';env=dict(os.environ,MTOOLS_SKIP_CHECK='1')
 def run(*a):return subprocess.run(a,check=True,capture_output=True,env=env)
 run('mdeltree','-i',spec,'::/FLYING');run('mmd','-i',spec,'::/FLYING')
 source=ROOT/'emulation/usb_set_theme_catalogue_sandbox.c';module=out/'catalogue.out'
 command=['clang','--target=powerpc-unknown-linux-gnu','-mbig-endian','-m32','-mlongcall','-ffreestanding','-fno-pic','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-msoft-float','-I',str(out),'-I',str(ROOT/'emulation'),'-O2','-Wall','-Wextra','-Werror','-c',str(source),'-o',str(module)]
 subprocess.run(command,check=True);data=module.read_bytes();body=(f'{crc16(data):04x}\r\nVER:SMEG5.43.A.R2\r\nTYPE:RELOCABLE\r\nID:0\r\nCOMPRESSED:NO\r\nSIZE:{len(data)}\r\nENTRY:YES\r\n').encode();doctor=b'0000\r\nACTION:TemporaryBootRom\r\nLOAD_AND_EXECUTE:/bd0/FLYING/catalogue.out\r\n'
 files={'FLYING/catalogue.out':data,'FLYING/catalogue.out.inf':f'{crc16(body):04x}'.encode()+body,'FLYING/doctor_smeg_plus_i.inf':f'{crc16(doctor):04x}'.encode()+doctor}
 with tempfile.TemporaryDirectory()as td:
  for i,(name,data)in enumerate(files.items()):
   p=Path(td)/str(i);p.write_bytes(data);run('mcopy','-i',spec,str(p),'::/'+name);assert run('mtype','-i',spec,'::/'+name).stdout==data
 (out/'usb.json').write_text(json.dumps(dict(emulator_only=True,physical_car_approved=False,physical_device_access=False,requested_common_keys=rows,image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),compile_command=command),indent=2)+'\n');print(image)
if __name__=='__main__':main()
