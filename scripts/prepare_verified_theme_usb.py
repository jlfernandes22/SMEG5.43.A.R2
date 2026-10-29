#!/usr/bin/env python3
"""Check/write one explicitly configured USB after QEMU validation.

Default is read-only preflight. --write destroys this USB's partition layout;
original exports must already be independently backed up. This never accesses
the car, nor establishes physical firmware recovery or compatibility.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess

from local_device_config import load_local_device_config

ROOT = Path(__file__).resolve().parents[1]
PHASE = ROOT/'artifacts/phase15'
_LOCAL_DEVICE = load_local_device_config()
DEVICE = Path(_LOCAL_DEVICE.get('usb_device', '/dev/disk/by-id/SMEG_USB_NOT_CONFIGURED'))
SERIAL = _LOCAL_DEVICE.get('usb_serial', '')
CAPACITY = _LOCAL_DEVICE.get('usb_capacity_bytes', 0)
MODEL = _LOCAL_DEVICE.get('usb_model', '')


def require(test, message):
    if not test:
        raise ValueError(message)


def sha(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f,'sha256').hexdigest()


def validate_receipts(image, verification):
    require(image.is_relative_to(PHASE) and image.is_file() and not image.is_symlink(), 'Only Phase15 image permitted')
    require(stat.S_ISREG(image.stat().st_mode) and image.stat().st_size == 2*1024**3, 'Expected regular 2GiB image')
    validation = json.loads((image.parent/'candidate-validation.json').read_text())
    independent = json.loads((image.parent/'candidate-independent-audit.json').read_text())
    # Independent audits are detailed evidence rather than an approval flag.
    image_sha=sha(image)
    require(validation['virtual_USB']['sha256'] == image_sha and independent.get('virtual_USB_sha256') == image_sha,
            'Candidate/independent image hash mismatch')
    readback=independent.get('virtual_USB_readback',{})
    require(independent.get('all12_asset_files_match_manifest') is True
            and independent.get('exact_SQL_change_count') == 20
            and independent.get('all_other_SQL_rows_columns_and_schema_preserved') is True
            and independent.get('audit_sources_and_original_backups_unchanged') is True
            and readback.get('all_hashes_match') is True
            and readback.get('all_package_members_readback_verified') == len(independent.get('all_package_file_sha256',{}))
            and readback.get('all_package_members_readback_verified',0) >= 151,
            'Independent package/USB audit incomplete')
    proof = json.loads(verification.read_text())
    require(proof.get('candidate_USB_sha256') == image_sha, 'Test evidence does not bind this exact USB image')
    require(proof.get('exact_native_USB_install_and_cold_boot_verified') is True,
            'Exact package native installation and USB-free cold boot are not yet verified')
    require(proof.get('all_eight_theme_switches_visually_verified') is True,
            'Every theme must be visually verified after native selection/reboot')
    require(proof.get('all_eight_themes_Internet_menu_verified') is True,
            'Internet navigation must be verified on every theme')
    require(proof.get('unresolved_compatibility_issues') == [],
            'Unresolved theme/menu compatibility issues remain')
    require(set(proof.get('verified_theme_names',[])) ==
            {'GRAPHIC','ELLIPTIC','CUBIC','REFLEX','ESSENTIEL','REDLINE','SQUARE','WARMLIGHT'},
            'Incomplete actual theme coverage')
    require(proof.get('fatal_guest_exceptions') == [], 'Unresolved guest exceptions')
    original = ROOT/'artifacts/live_car_backup/2026-10-27-native-usb'
    manifest = json.loads((original/'copy-manifest.json').read_text())
    require(len(manifest['files']) == 34, 'Original backup manifest mismatch')
    usb_backup = PHASE/'usb-before-preparation/files'
    for row in manifest['files']:
        for path in (original/'usb'/row['path'],usb_backup/row['path']):
            require(path.is_file() and not path.is_symlink() and sha(path)==row['sha256'],
                    'Original USB export not safely preserved: '+str(path))
    return proof


def block_nodes(nodes):
    for node in nodes:
        yield node
        yield from block_nodes(node.get('children') or [])


def device_state():
    require(SERIAL and CAPACITY > 0 and MODEL and str(DEVICE).startswith('/dev/disk/by-id/')
            and DEVICE.name != 'SMEG_USB_NOT_CONFIGURED',
            'Configure an explicit USB identity in .smeg-local.json or SMEG_USB_* first')
    info = json.loads(subprocess.check_output(['lsblk','--json','--bytes','--tree','--output',
        'NAME,PATH,TYPE,MAJ:MIN,SIZE,MODEL,SERIAL,TRAN,RM,RO,MOUNTPOINTS']))['blockdevices']
    found = [d for d in block_nodes(info) if d.get('serial') == SERIAL]
    require(len(found)==1, 'Expected exactly one explicitly identified USB')
    d=found[0]
    require(DEVICE.exists() and DEVICE.resolve()==Path(d['path']), 'Stable device ID mismatch')
    require(d.get('type')=='disk' and d.get('tran')=='usb' and d.get('rm') in (True,1)
            and d.get('ro') in (False,0) and str(d.get('model','')).strip()==MODEL,
            'Device is not the authorized removable USB')
    require(int(d['size'])==CAPACITY, 'USB capacity changed; inspect identity rather than guessing')
    device_stat=DEVICE.stat()
    require(stat.S_ISBLK(device_stat.st_mode), 'Expected a block device')
    require(d.get('maj:min') == f'{os.major(device_stat.st_rdev)}:{os.minor(device_stat.st_rdev)}',
            'Kernel device identity disagrees with lsblk')
    return d, [m for n in block_nodes([d]) for m in (n.get('mountpoints') or []) if m]


def validate_open_device(fd, device):
    """Check the exclusive descriptor before any write, guarding path swaps."""
    opened=os.fstat(fd)
    require(stat.S_ISBLK(opened.st_mode) and
            device['maj:min']==f'{os.major(opened.st_rdev)}:{os.minor(opened.st_rdev)}',
            'Opened device differs from verified USB')
    size=struct.unpack('=Q',fcntl.ioctl(fd,0x80081272,b'\0'*8))[0]  # BLKGETSIZE64
    require(size==CAPACITY,'Opened USB capacity mismatch')


def progress(phase, done, total):
    print(json.dumps({'phase':phase,'completed_bytes':done,'total_bytes':total,
                      'percent':round(done*100/total,1)}),flush=True)


def validate_open_source(source, expected_sha256, expected_bytes=2*1024**3):
    """Pin the tested bytes on a held read-only descriptor before device open."""
    info=os.fstat(source.fileno())
    require(stat.S_ISREG(info.st_mode) and info.st_size==expected_bytes,
            'Opened source is not the validated regular image geometry')
    source.seek(0)
    require(hashlib.file_digest(source,'sha256').hexdigest()==expected_sha256,
            'Opened source differs from the exact tested image; USB was not opened')
    source.seek(0)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image',type=Path,required=True)
    p.add_argument('--verification',type=Path,required=True)
    p.add_argument('--write',action='store_true')
    a=p.parse_args()
    require(not a.image.is_symlink() and not a.verification.is_symlink(), 'Symlink inputs refused')
    image=a.image.resolve(); verification=a.verification.resolve()
    require(verification.is_relative_to(PHASE) and verification.is_file(), 'Only Phase15 verification permitted')
    proof=validate_receipts(image,verification)
    device,mounted=device_state()
    report={'device':str(DEVICE),'resolved_device':device['path'],'serial':SERIAL,
            'capacity':int(device['size']),'image':str(image),'image_sha256':proof['candidate_USB_sha256'],
            'physical_car_accessed':False,'physical_car_recovery_verified':False,
            'emulator_proof':str(verification),'mounted':mounted,'USB_written':False}
    if not a.write:
        print(json.dumps(report,indent=2));return
    output=PHASE/'physical-usb-preparation.json'
    require(not output.exists(),'Physical preparation receipt already exists; do not overwrite history')
    require(os.geteuid()==0,'Root/device-restore authorization required for physical USB preparation')
    require(not mounted,'Unmount the identified USB before whole-device writing')
    # Recheck identity immediately before exclusive opening. Linux refuses the
    # exclusive whole-disk open if a partition has been mounted meanwhile.
    source_fd=os.open(image,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(source_fd,'rb') as source:
        validate_open_source(source,report['image_sha256'])
        device, mounted=device_state(); require(not mounted,'USB became mounted')
        fd=os.open(DEVICE,os.O_RDWR|os.O_EXCL)
        try:
            validate_open_device(fd,device)
            total=2*1024**3;done=0;milestone=0;copied_digest=hashlib.sha256()
            progress('writing_identified_USB',0,total)
            while done<total:
                chunk=source.read(min(8*1024**2,total-done));require(chunk,'Source became truncated during USB preparation')
                copied_digest.update(chunk)
                view=memoryview(chunk)
                while view:
                    written=os.write(fd,view);require(written>0,'Short device write');view=view[written:]
                done+=len(chunk)
                if done*10//total>milestone:
                    milestone=done*10//total;progress('writing_identified_USB',done,total)
            require(not source.read(1),'Source image grew during USB preparation')
            require(copied_digest.hexdigest()==report['image_sha256'],
                    'Source changed during writing; USB is not ready for use')
            os.fsync(fd)
            fcntl.ioctl(fd,0x1261)  # BLKFLSBUF: flush and invalidate host block cache.
            os.lseek(fd,0,os.SEEK_SET);left=total;digest=hashlib.sha256()
            milestone=0;progress('verifying_USB_readback',0,total)
            while left:
                chunk=os.read(fd,min(left,8*1024**2));require(chunk,'Truncated device readback')
                digest.update(chunk);left-=len(chunk)
                if (total-left)*10//total>milestone:
                    milestone=(total-left)*10//total;progress('verifying_USB_readback',total-left,total)
            require(digest.hexdigest()==report['image_sha256'],'USB readback differs; do not insert into the car')
            report.update(USB_written=True,prefix_readback_bytes=total,
                          prefix_readback_sha256=digest.hexdigest(),readback_verified=True,
                          held_source_stream_sha256=copied_digest.hexdigest())
            fcntl.ioctl(fd,0x125f)  # BLKRRPART: reread the new partition table.
        finally:
            os.close(fd)
    output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__':
    main()
