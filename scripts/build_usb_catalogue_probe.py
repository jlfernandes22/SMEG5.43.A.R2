#!/usr/bin/env python3
"""QEMU-only one-integer native catalogue refresh probe. No resource payload."""
import argparse,hashlib,json,os,shutil,subprocess,tempfile
from pathlib import Path
from smeg_db_inf import crc16
from build_usb_resource_probe import fnv
ROOT=Path(__file__).resolve().parents[1]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,default=ROOT/'artifacts/phase20/catalogue-native-probe');p.add_argument('--marker-only',action='store_true');a=p.parse_args()
 out=a.output.resolve();assert out.is_relative_to(ROOT/'artifacts/phase20')and not out.exists();out.mkdir()
 image=out/'usb.raw';shutil.copyfile(ROOT/'artifacts/phase11/usb-capabilities/read-only/usb.raw',image)
 spec=str(image)+'@@1048576';env=dict(os.environ,MTOOLS_SKIP_CHECK='1')
 def run(*a):return subprocess.run(a,check=True,capture_output=True,env=env)
 run('mdeltree','-i',spec,'::/FLYING');run('mmd','-i',spec,'::/FLYING')
 shutil.copyfile(ROOT/'artifacts/phase20/theme-activation-probe-v3/usb_warmlight_api_fingerprints.h',out/'usb_warmlight_api_fingerprints.h')
 app=(ROOT/'artifacts/phase2/applications/AUDIO_BT_256/app.bin').read_bytes()
 checks=[dict(address=a,hash=fnv(app[a-0x1000000:a-0x1000000+64]))for a in (0x1110a64,0x11124e0)]
 (out/'theme_catalogue_contract.h').write_text('struct CatalogueAPI{unsigned address,hash;};\nstatic const struct CatalogueAPI catalogue_api[]={'+','.join('{0x%xu,0x%xu}'%(r['address'],r['hash'])for r in checks)+'};\n')
 owners=[dict(address=v,hash=fnv(app[v-0x1000000:v-0x1000000+64]))for v in (0x186f00c,0x1874884)]
 with (out/'theme_catalogue_contract.h').open('a')as f:f.write('static const struct CatalogueAPI catalogue_owner[]={'+','.join('{0x%xu,0x%xu}'%(r['address'],r['hash'])for r in owners)+'};\n')
 module=out/'catalogue.out';source=ROOT/'emulation/usb_refresh_theme_catalogue_sandbox.c'
 command=['clang','--target=powerpc-unknown-linux-gnu','-mbig-endian','-m32','-mlongcall','-ffreestanding','-fno-pic','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-msoft-float','-I',str(out),'-I',str(ROOT/'emulation'),'-O2','-Wall','-Wextra','-Werror','-c',str(source),'-o',str(module)]
 if a.marker_only:command.insert(1,'-DSMEG_CATALOGUE_MARKER_ONLY=1')
 subprocess.run(command,check=True);data=module.read_bytes()
 body=(f'{crc16(data):04x}\r\nVER:SMEG5.43.A.R2\r\nTYPE:RELOCABLE\r\nID:0\r\nCOMPRESSED:NO\r\nSIZE:{len(data)}\r\nENTRY:YES\r\n').encode()
 doctor=b'0000\r\nACTION:TemporaryBootRom\r\nLOAD_AND_EXECUTE:/bd0/FLYING/catalogue.out\r\n'
 files={'FLYING/catalogue.out':data,'FLYING/catalogue.out.inf':f'{crc16(body):04x}'.encode()+body,'FLYING/doctor_smeg_plus_i.inf':f'{crc16(doctor):04x}'.encode()+doctor}
 with tempfile.TemporaryDirectory()as td:
  for i,(name,data)in enumerate(files.items()):
   p=Path(td)/str(i);p.write_bytes(data);run('mcopy','-i',spec,str(p),'::/'+name);assert run('mtype','-i',spec,'::/'+name).stdout==data
 (out/'usb.json').write_text(json.dumps(dict(emulator_only=True,physical_car_approved=False,physical_device_access=False,requested_key={}if a.marker_only else{'upgrade.HarmoniesChecked.IntValue':[5,0]},removed_cache_marker='/SYSTEM_TMP_DATA/HarmoniesChecked.tst'if a.marker_only else None,image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),API_checks=checks,compile_command=command),indent=2))
 print(image)
if __name__=='__main__':main()
