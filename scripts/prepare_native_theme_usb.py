#!/usr/bin/env python3
"""Prepare only the pinned Verbatim with the exact tested theme-only image.

Default is read-only preflight. Requires completed native USB/cold-boot evidence,
independent payload/database audits, and a fresh backup of every old USB file.
Writing media does not certify physical-car compatibility or power-loss recovery.
"""
import argparse,datetime,fcntl,hashlib,json,os
from pathlib import Path
from prepare_verified_theme_usb import DEVICE,SERIAL,ROOT,require,device_state,validate_open_device,validate_open_source
from prepare_warmlight_test_usb import verify_prefix,replace_prefix

BASE=ROOT/'artifacts/phase20'
IMAGE=BASE/'complete-stock-probe-v7/usb.raw'
PROOF=BASE/'physical-theme-preparation-proof.json'
BACKUP=BASE/'physical-before'
RECEIPT=BASE/'physical-theme-usb-preparation.json'

def digest(path):
    with path.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()

def proofs():
    proof=json.loads(PROOF.read_text());metadata=json.loads((IMAGE.parent/'usb.json').read_text())
    require(proof['single_USB_stock_to_eight_theme_install_and_cold_boot_verified']is True,'Exact complete native installation and cold-boot proof required')
    require(proof['candidate_USB_sha256']==metadata['image_sha256']==digest(IMAGE),'Exact tested media changed')
    require(proof['original_application_binary_byte_exact']and proof['selected_WARMLIGHT_preserved']and
            proof['all_seven_databases_integrity_INF_valid']and proof['unexpected_non_theme_setting_changes']==[],'Preservation checks failed')
    require(set(proof['verified_theme_names'])=={'GRAPHIC','ELLIPTIC','CUBIC','REFLEX','ESSENTIEL','REDLINE','SQUARE','WARMLIGHT'},'Incomplete native theme coverage')
    require(proof['critical_guest_failures']==[],'Unresolved critical guest failure')
    require(metadata['complete_stock_to_eight_theme_installer']and metadata['full_native_payload_backup_and_readback']and
            metadata['generated_theme_cache_marker_invalidated']and metadata['removed_cache_marker']=='/SYSTEM_TMP_DATA/HarmoniesChecked.tst',
            'Unexpected installer scope')
    require(not metadata['replacement_databases']and not metadata['application_or_BSP_writes']and not metadata['auto_reboot'],'Unexpected system replacement or reboot')
    require(metadata['requested_configuration_flags']==['display.Harm_'+str(uid)+'.0=1'for uid in (1,2,3,4,7,8)],'Unexpected settings request')
    expected_rows=[]
    for uid,name,number,code in [(1,'GRAPHIC',1,102),(2,'ELLIPTIC',1,202),(3,'CUBIC',2,203),(4,'REFLEX',3,204),(7,'ESSENTIEL',3,104),(8,'REDLINE',2,103)]:
        expected_rows.extend([dict(Section='supervisor',Name=f'harmony{uid}',Idx=0,StringValue=name),
                              dict(Section='supervisor',Name=f'harm{uid}_number',Idx=0,IntValue=number),
                              dict(Section='supervisor',Name=f'harm{uid}_offset_area',Idx=0,IntValue=code)])
    require(metadata['native_theme_catalogue_registration']is True and metadata['requested_theme_catalogue_rows']==expected_rows,
            'Unexpected native theme catalogue changes')
    names={r['path']for r in metadata['files']}
    expected={'FLYING/theme_resources.out','FLYING/theme_resources.out.inf','FLYING/doctor_smeg_plus_i.inf',
              *[f'THEME_TEST/bank{n}.bin'+suffix for n in (1,2)for suffix in ('','.inf')],
              *[f'PREVIEWS/theme{uid}.jpg'for uid in (1,2,3,4,7,8)]}
    require(names==expected,'Unexpected USB payload members')
    for row in proof['evidence']:
        p=Path(row['path']);require(p.is_relative_to(ROOT/'artifacts')and not p.is_symlink()and digest(p)==row['sha256'],'Bound evidence changed')
    manifest=json.loads((BACKUP/'copy-manifest.json').read_text())
    require(manifest['USB_serial']==SERIAL and manifest['read_only_mount']and len(manifest['files'])>=27,'Fresh USB file backup incomplete')
    for row in manifest['files']:
        p=BACKUP/'files'/row['path'];require(p.is_relative_to(BACKUP/'files')and not p.is_symlink()and p.stat().st_size==row['bytes']and digest(p)==row['sha256'],'Old USB file backup mismatch')
    require(proof['physical_car_compatibility_certified']is False,'Do not misrepresent emulator evidence as physical certification')
    return proof,metadata

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');a=p.parse_args()
    proof,metadata=proofs();device,mounted=device_state();size=IMAGE.stat().st_size
    require(size==135266304 and not IMAGE.is_symlink(),'Unexpected image type/geometry')
    report=dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),USB_serial=SERIAL,
                resolved_device=device['path'],image=str(IMAGE),image_sha256=metadata['image_sha256'],image_bytes=size,
                physical_car_accessed=False,physical_car_compatibility_certified=False,USB_written=False,
                scope='Experimental theme-only installer; inserting it triggers native maintenance',
                stock_originals_backed_up_first=True,theme_banks_rewritten=[1,2],OS_binary_replacements=False,
                custom_apps_or_network_changes=False,known_cosmetic_limitations=proof['known_cosmetic_limitations'])
    with os.fdopen(os.open(IMAGE,os.O_RDONLY|os.O_NOFOLLOW),'rb')as source:
        validate_open_source(source,metadata['image_sha256'],size)
        if not a.write:print(json.dumps(report,indent=2));return
        require(os.geteuid()==0,'Administrator authentication required')
        require(not RECEIPT.exists(),'Existing preparation receipt must be preserved')
        require(not mounted,'USB must be unmounted')
        device,mounted=device_state();require(not mounted,'USB became mounted')
        fd=os.open(DEVICE,os.O_RDWR|os.O_EXCL)
        try:
            validate_open_device(fd,device);old=BACKUP/'original-prefix.raw';h=hashlib.sha256();left=size
            with old.open('xb')as saved:
                while left:
                    chunk=os.read(fd,min(left,8<<20));require(chunk,'Truncated device prefix');saved.write(chunk);h.update(chunk);left-=len(chunk)
                saved.flush();os.fsync(saved.fileno())
            require(old.stat().st_size==size and digest(old)==h.hexdigest(),'Original raw-prefix backup failed')
            report.update(original_prefix_backup=str(old),original_prefix_sha256=verify_prefix(fd,size,h.hexdigest()))
            report['readback_sha256']=replace_prefix(fd,source,size,metadata['image_sha256'])
            report.update(USB_written=True,readback_verified=True);fcntl.ioctl(fd,0x125f)
        finally:os.close(fd)
    RECEIPT.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))

if __name__=='__main__':main()
