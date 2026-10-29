#!/usr/bin/env python3
"""Artifact-only stock firmware plus byte-exact original live database restore.

Downloaded factory firmware is not a physical binary dump. Original metadata stays byte-exact; added USER_DATA files are outside its listed checks. This cannot force recovery if bootloader/updater is unreachable.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import struct
import subprocess
import sys
import zlib

ROOT=Path(__file__).resolve().parents[1]
ALLOWED=ROOT/'artifacts/phase14/stock-restore'
sys.path.insert(0,str(ROOT/'scripts'))
from build_franken_candidate import SOURCE, ORIGINAL, sha
from package_database_update import validate_contract
from smeg_db_inf import verify_inf
from ensure_smeg_fat_lfn import Fat32, lfn_record


def require(condition,message):
    if not condition:raise ValueError(message)


def inventory(root):
    result={}
    for p in sorted(root.rglob('*')):
        require(not p.is_symlink(),'Source symlink refused: '+str(p))
        if p.is_file():result[str(p.relative_to(root))]={'bytes':p.stat().st_size,'sha256':sha(p)}
    return result


def verify_backup():
    manifest=json.loads((ORIGINAL/'copy-manifest.json').read_text())
    require(len(manifest['files'])==34,'Expected original 34-file backup manifest')
    for item in manifest['files']:
        p=ORIGINAL/'usb'/item['path']
        require(p.resolve().is_relative_to(ORIGINAL.resolve()) and not p.is_symlink(),'Unsafe backup path')
        require(sha(p)==item['sha256'],'Backup hash mismatch: '+item['path'])
    return manifest


def verify_usb_tree(image,package):
    expected={k.casefold():v for k,v in inventory(package).items()}
    actual={}
    with image.open('rb') as stream:
        volume=Fat32(stream,image.stat().st_size)
        def visit(cluster,prefix=''):
            for entry in volume.entries(cluster):
                if entry['short'] in ('.','..'):continue
                name=entry['lfn'] or entry['short'];relative=prefix+name
                if entry['attr']&16:visit(entry['cluster'],relative+'/');continue
                if entry['attr']&8:continue
                digest=hashlib.sha256();left=entry['bytes']
                if left:
                    for current in volume.clusters(entry['cluster']):
                        take=min(left,volume.cluster_bytes)
                        digest.update(volume.read(volume.data+(current-2)*volume.cluster_bytes,take));left-=take
                        if not left:break
                require(left==0,'Truncated image member: '+relative)
                require(relative.casefold().startswith('smeg_plus_upg/'),'Unexpected USB-root payload')
                key=relative.split('/',1)[1].casefold();require(key not in actual,'Duplicate FAT member')
                actual[key]={'bytes':entry['bytes'],'sha256':digest.hexdigest()}
        visit(volume.root)
    require(actual==expected,'USB package readback differs from validated host tree')
    return {'all_package_members_readback_verified':len(actual),'all_hashes_match':True}


def make_usb(package,image,expected):
    size=2*1024**3;first=2048;sectors=size//512-first
    mbr=bytearray(512);mbr[446:462]=struct.pack('<B3sB3sII',0,b'\xfe\xff\xff',12,b'\xfe\xff\xff',first,sectors);mbr[510:]=b'\x55\xaa'
    with image.open('xb') as f:f.truncate(size);f.write(mbr)
    subprocess.run(['mkfs.vfat','-F','32','-n','SMEG_STOCK','--offset',str(first),str(image),str(sectors//2)],check=True,capture_output=True)
    subprocess.run(['mcopy','-s','-i',str(image)+'@@1048576',str(package),'::/'],check=True,capture_output=True,env=dict(os.environ,MTOOLS_SKIP_CHECK='1'))
    with image.open('r+b') as f:
        volume=Fat32(f,size);parent,target,_=volume.target();before=volume.payload_hashes(target['cluster'])
        if target['lfn']!='sqlite':
            require(not target['lfn_offsets'],'Unexpected existing non-lowercase LFN')
            slots=list(volume.slots(parent));i=next(i for i,(off,_) in enumerate(slots) if off==target['offset'])
            require(i+2<len(slots) and slots[i+1][1][0] in (0,229),'No free adjacent LFN slot')
            raw=bytes.fromhex(target['raw_hex']);f.seek(target['offset']);f.write(lfn_record('sqlite',raw[:11]));f.seek(slots[i+1][0]);f.write(raw);f.flush();os.fsync(f.fileno())
        _,target,_=volume.target();require(target['lfn']=='sqlite','Literal sqlite LFN missing')
        after=volume.payload_hashes(target['cluster']);require(before==after,'LFN edit changed payloads')
        require({k.casefold():v for k,v in after.items()}=={Path(k).name.casefold():v for k,v in expected.items()},'Virtual USB database readback mismatch')
    return {**verify_usb_tree(image,package),'path':str(image),'bytes':size,'sha256':sha(image),'FAT32_MBR_partition_offset':1048576,'native_literal_sqlite_LFN_verified':True,'all14_database_pair_files_readback_verified':True,'physical_devices_accessed':False}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,default=ALLOWED/'candidate/SMEG_PLUS_UPG');p.add_argument('--image',type=Path)
    a=p.parse_args();out=a.output.resolve();image=a.image.resolve() if a.image else None
    require(out.is_relative_to(ALLOWED) and out.name=='SMEG_PLUS_UPG' and not a.output.is_symlink(),'Only new stock-restore artifact package permitted')
    require(not out.exists(),'Output exists; refusing overwrite')
    require(not (out.parent/'validation.json').exists() and not (out.parent/'ARTIFACT_ONLY.txt').exists(),'Candidate reports exist; refusing overwrite')
    if image:require(image.is_relative_to(ALLOWED) and image.suffix=='.raw' and not a.image.is_symlink() and not image.exists(),'Only new stock-restore .raw artifact permitted')
    before=inventory(SOURCE)
    historic={}
    for line in (ROOT/'artifacts/phase2/firmware-inventory.jsonl').read_text().splitlines():
        item=json.loads(line);prefix='artifacts/phase2/package/SMEG_PLUS_UPG/'
        if item['path'].startswith(prefix):historic[item['path'][len(prefix):]]={'bytes':item['size'],'sha256':item['sha256']}
    require(before==historic,'Factory source differs from Phase2 original inventory')
    manifest=verify_backup();backup=ORIGINAL/'usb/SMEG_BACKUP'
    require(len(list(backup.glob('*.sqlite')))==7,'Expected seven original databases')
    out.parent.mkdir(parents=True,exist_ok=True);shutil.copytree(SOURCE,out,copy_function=shutil.copy2)
    members=[];dbs=[];expected={}
    for source in sorted(backup.glob('*.sqlite')):
        stored=source.read_bytes();raw=gzip.decompress(stored) if stored[:2]==b'\x1f\x8b' else stored;sidecar=source.with_name(source.name+'.inf')
        require(verify_inf(raw,stored,sidecar.read_bytes()),'Invalid database INF: '+source.name)
        c=sqlite3.connect(':memory:');c.deserialize(raw);c.execute('PRAGMA trusted_schema=OFF');require(c.execute('PRAGMA integrity_check').fetchall()==[('ok',)],'SQLite integrity failure');c.close()
        for src in [source,sidecar]:
            rel='NAV/USER_DATA/user_data/sqlite/'+src.name;dest=out/rel;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dest);require(sha(src)==sha(dest),'Restore payload changed');members.append(rel);expected[rel]={'bytes':dest.stat().st_size,'sha256':sha(dest)}
        dbs.append({'name':source.name,'sqlite_integrity':'ok','INF_verified':True,'stored_bytes_unchanged':True,'database_and_INF_sha256':{x.name:sha(x) for x in [source,sidecar]}})
    metadata={'membership_policy':'unchanged factory manifests; native USER_DATA xcopy independent'}
    metadata['USER_DATA_security_boundary']='New USER_DATA files are not covered by original listed control/contract checks; original DB+INF validated independently.'
    controls=[];contract=validate_contract(out)
    contract['original_factory_metadata_byte_exact']=True
    changed=[]
    for rel,item in before.items():
        require((out/rel).is_file(),'Missing factory member: '+rel)
        if sha(out/rel)!=item['sha256']:changed.append(rel)
    require(not changed,'Factory file mutated: '+str(changed))
    require(inventory(SOURCE)==before,'Factory source changed');verify_backup()
    report={'artifact_only':True,'physical_car_access':False,'physical_car_approved':False,'physical_binary_dump_available':False,'firmware_source':'Downloaded original SMEG5.43.A.R2 package; not read back from physical unit','live_backup_scope':'Seven original database+INF pairs only; all34 copied backup files hash-verified before and after','factory_source_inventory':before,'factory_source_matches_original_phase2_inventory':True,'factory_files_count':len(before),'factory_payloads_byte_exact':True,'changed_factory_metadata_only':changed,'database_pairs':dbs,'new_restore_members':expected,'metadata':metadata,'control_cascade':controls,'contract':contract,'vendor_signing_claim':False,'native_update_test_completed':False,'recovery_limit':'Cannot force USB recovery if bootloader/updater is unreachable','native_test_command':'SMEG_CASE=stockrestore SMEG_NAND=<PRIVATE_COPIED_NAND.raw> SMEG_USB_MEDIA='+str(image or '<USB.raw>')+' SMEG_FRONT_PANEL=0 bash emulation/launch_features.sh'}
    if image:image.parent.mkdir(parents=True,exist_ok=True);report['virtual_USB']=make_usb(out,image,expected)
    verify_backup();require(inventory(SOURCE)==before,'Factory source changed after USB creation')
    (out.parent/'validation.json').write_text(json.dumps(report,indent=2)+'\n')
    (out.parent/'ARTIFACT_ONLY.txt').write_text('Untested native restore candidate. No physical install authorization. Original downloaded firmware payloads plus exact original live databases; all factory metadata byte-exact; no vendor signing. Cannot force USB recovery if updater/bootloader unreachable.\n')
    print(json.dumps({'candidate':str(out),'factory_files':len(before),'modified_metadata':changed,'database_pairs':len(dbs),'image':str(image) if image else None}))
if __name__=='__main__':main()
