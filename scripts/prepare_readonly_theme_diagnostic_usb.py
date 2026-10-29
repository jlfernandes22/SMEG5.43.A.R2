#!/usr/bin/env python3
"""Prepare only the identified Verbatim with the verified read-only diagnostic.

Default is read-only preflight. Save all returned physical receipts first.
The diagnostic replaces the theme-writing module; it cannot install themes.
"""
import argparse,datetime,fcntl,hashlib,json,os
from pathlib import Path
from prepare_verified_theme_usb import ROOT,DEVICE,SERIAL,require,device_state,validate_open_device,validate_open_source
from prepare_warmlight_test_usb import verify_prefix,replace_prefix
BASE=ROOT/'artifacts/phase21';PROBE=BASE/'read-only-source-diagnostic-v1';OLD=BASE/'physical-theme-return-2026-10-29'
def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');a=p.parse_args();meta=json.loads((PROBE/'usb.json').read_text());proof=json.loads((PROBE/'verification.json').read_text());image=PROBE/'usb.raw';size=image.stat().st_size
 require(size==135266304 and sha(image)==meta['image_sha256']==proof['image_sha256'],'Tested image changed')
 require(proof['native_test_complete']and proof['all_three_stock_application_and_theme_containers_exact']and proof['all_seven_databases_valid']and len(proof['checks'])==6,'Native diagnostic validation incomplete')
 require(not meta['NAND_write_APIs']and not meta['configuration_setters']and not meta['automatic_reboot']and meta['old_installer_removed'],'Wrong module scope')
 require(sha(ROOT/'emulation/usb_theme_source_diagnostic.c')==meta['source_sha256']==proof['source_sha256'],'Diagnostic source changed')
 manifest=json.loads((OLD/'copy-manifest.json').read_text());require(manifest['USB_serial']==SERIAL and manifest['read_only_mount']and len(manifest['files'])==32,'Physical return backup incomplete')
 for row in manifest['files']:
  file=OLD/'files'/row['path'];require(not file.is_symlink()and file.stat().st_size==row['bytes']and sha(file)==row['sha256'],'Returned evidence changed')
 device,mounted=device_state();report=dict(USB_serial=SERIAL,image_sha256=meta['image_sha256'],USB_written=False,read_only_car_diagnostic=True,theme_installer_removed=True,vehicle_setting_changes=False,physical_car_accessed=False,created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
 if not a.write:print(json.dumps(report,indent=2));return
 require(os.geteuid()==0 and not mounted,'Administrator access and unmounted USB required')
 receipt=BASE/'physical-readonly-diagnostic-preparation.json';require(not receipt.exists(),'Preserve previous receipt')
 with os.fdopen(os.open(image,os.O_RDONLY|os.O_NOFOLLOW),'rb')as source:
  validate_open_source(source,meta['image_sha256'],size);device,mounted=device_state();require(not mounted,'USB became mounted');fd=os.open(DEVICE,os.O_RDWR|os.O_EXCL)
  try:
   validate_open_device(fd,device);saved=OLD/'original-prefix.raw';h=hashlib.sha256();left=size
   with saved.open('xb')as backup:
    while left:
     data=os.read(fd,min(left,8<<20));require(data,'Short backup read');backup.write(data);h.update(data);left-=len(data)
    backup.flush();os.fsync(backup.fileno())
   require(sha(saved)==h.hexdigest(),'Physical-return prefix backup failed');report['original_prefix_sha256']=verify_prefix(fd,size,h.hexdigest());report['original_prefix_backup']=str(saved)
   report['readback_sha256']=replace_prefix(fd,source,size,meta['image_sha256']);report.update(USB_written=True,readback_verified=True);fcntl.ioctl(fd,0x125f)
  finally:os.close(fd)
 receipt.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
