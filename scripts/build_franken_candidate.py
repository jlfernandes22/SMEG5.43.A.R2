#!/usr/bin/env python3
"""Prepare an emulator-only native-updater candidate, never a physical device.

Preserves both application streams, validates the native checksum cascade and
re-encodes the existing contract format. This is not vendor approval/signing or
evidence that the native updater installed it. Original car backups are read-only.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import struct
import subprocess
import sys
import zlib

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'artifacts/phase2/package/SMEG_PLUS_UPG'
ORIGINAL=ROOT/'artifacts/live_car_backup/2026-10-27-native-usb'
sys.path.insert(0,str(ROOT/'sources/smeg-plus-patches/tools'))
from smeglib import ctrl_crc16, has_ctrl_layout, has_trailer
from patch_contract import find_keys,inflate,load_contract,check_of,rebuild_record,encrypt_block
from smeg_db_inf import encode_inf,verify_inf
from create_smeg_virtual_usb import create


def sha(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()


def resolve(root,name):
    parts=name.lstrip('/').split('/')
    if parts[0]=='SMEG_PLUS_UPG':parts.pop(0)
    current=root
    for part in parts:
        found=[x for x in current.iterdir() if x.name.casefold()==part.casefold()] if current.is_dir() else []
        if len(found)!=1:return None
        current=found[0]
    return current if current.is_file() else None


def update_controls(package):
    changes=[]
    controls=sorted(package.rglob('*ctrl.bin'),key=lambda p:len(p.parts),reverse=True)
    # Root has the same depth as module controls: process it last explicitly.
    controls=[p for p in controls if p.name!='ctrl.bin']+[package/'ctrl.bin']
    for path in controls:
        old=path.read_bytes();assert has_ctrl_layout(old) and has_trailer(old)
        buf=bytearray(old)
        for i in range(struct.unpack_from('>I',old,44)[0]):
            offset=48+264*i;record=old[offset:offset+264]
            name=record[:256].split(b'\0')[0].decode();target=resolve(package,name)
            if target is None:continue # Unchanged members inside native system.bin tar.
            kind,previous=struct.unpack_from('>II',record,256);data=target.read_bytes()
            value=len(data) if kind==1 else zlib.crc32(data) if kind==2 else ctrl_crc16(data) if kind==3 else None
            assert value is not None
            if value!=previous:
                struct.pack_into('>I',buf,offset+260,value)
                changes.append({'control':str(path.relative_to(package)),'member':name,'check_type':kind,'old':hex(previous),'new':hex(value)})
        struct.pack_into('>I',buf,len(buf)-4,zlib.crc32(buf[:-4]));path.write_bytes(buf)
    # A second independent pass must not request any further cascade changes.
    for path in controls:
        d=path.read_bytes();assert has_trailer(d)
        for i in range(struct.unpack_from('>I',d,44)[0]):
            r=d[48+264*i:48+264*(i+1)];target=resolve(package,r[:256].split(b'\0')[0].decode())
            if target is None:continue
            kind,value=struct.unpack_from('>II',r,256);data=target.read_bytes()
            assert value==(len(data) if kind==1 else zlib.crc32(data) if kind==2 else ctrl_crc16(data))
    return changes


def seal_contract(package):
    keys=find_keys(inflate(SOURCE/'NAV/AppBin/f_BigQuick.bin'))
    header,records,key=load_contract(SOURCE/'contract.dat',keys)
    updated=[];changes=[]
    for rec in records:
        name=rec[:rec.index(b'\0')].decode();path=resolve(package,name);assert path is not None
        payload,kind=check_of(rec,path.read_bytes());new=rebuild_record(rec,payload);updated.append(new)
        if new!=rec:changes.append({'path':name,'check':kind})
    (package/'contract.dat').write_bytes(b''.join(encrypt_block(x,key) for x in [header]+updated))
    new_header,new_records,_=load_contract(package/'contract.dat',keys)
    assert new_header==header and new_records==updated
    return {'records_verified':len(records),'changed_records':changes,'key_material_logged':False,
            'existing_contract_format_reencoded':True,'vendor_signature_or_approval_generated':False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--variant',choices=['eligibility','eligibility-agenda'],default='eligibility-agenda')
    p.add_argument('--image',type=Path)
    p.add_argument('--all-live-databases',action='store_true',
        help='Recovery control: also ship byte-exact unchanged copies of the other six original databases')
    a=p.parse_args();out=a.output.resolve()
    assert out.is_relative_to(ROOT/'artifacts/phase13') and not out.exists() and out.name=='SMEG_PLUS_UPG'
    original_manifest=json.loads((ORIGINAL/'copy-manifest.json').read_text())
    for entry in original_manifest['files']:assert sha(ORIGINAL/'usb'/entry['path'])==entry['sha256']
    patched=ROOT/'artifacts/phase13/binary-analysis/v3'/a.variant/'f_BigQuick.bin'
    binary_manifest=json.loads((patched.parent.parent/'manifest.json').read_text())
    assert binary_manifest['variants'][a.variant]['container']['sha256']==sha(patched)
    out.parent.mkdir(parents=True,exist_ok=True)
    subprocess.run(['cp','--reflink=auto','-a',str(SOURCE),str(out)],check=True)
    app=out/'AUDIO_BT_256/AppBin/f_BigQuick.bin';app.write_bytes(patched.read_bytes())
    inf=Path(str(app)+'.inf');text,count=re.subn(rb'CRC32:\s*-?\d+',b'CRC32: '+str(struct.unpack('>i',struct.pack('>I',zlib.crc32(app.read_bytes())))[0]).encode(),inf.read_bytes());assert count==1;inf.write_bytes(text)
    # The native Phase6 filesystem copy also installs this profile metadata.
    # Keep its application CRC consistent with the exact packaged container,
    # then refresh every parent control/contract using the normal cascade.
    metadata=out/'AUDIO_BT_256/smeg.inf'
    application_crc=zlib.crc32(app.read_bytes())
    application_crc_signed=struct.unpack('>i',struct.pack('>I',application_crc))[0]
    text,count=re.subn(rb'BIGQUICK_CRC32:[ \t]*-?\d+',
        b'BIGQUICK_CRC32: '+str(application_crc_signed).encode(),metadata.read_bytes())
    assert count==1
    metadata.write_bytes(text)
    assets=ROOT/'artifacts/phase13/ui-assets/overlay'
    for src in assets.rglob('*'):
        if src.is_file():(out/src.relative_to(assets)).write_bytes(src.read_bytes())
    source_db=ORIGINAL/'usb/SMEG_BACKUP/up_config.sqlite';stored=source_db.read_bytes();raw=gzip.decompress(stored)
    assert verify_inf(raw,stored,Path(str(source_db)+'.inf').read_bytes())
    db=sqlite3.connect(':memory:');db.deserialize(raw)
    old=db.execute("SELECT * FROM UP_Keys WHERE Section='internet' AND Name='Web_active' AND Idx=0").fetchall()
    assert len(old)==1 and old[0][2]==2 and old[0][4]==0
    before={name:db.execute('SELECT * FROM "'+name.replace('"','""')+'"').fetchall() for name, in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    cursor=db.execute("UPDATE UP_Keys SET IntValue=1 WHERE Section='internet' AND Name='Web_active' AND Idx=0 AND Type=2 AND IntValue=0");assert cursor.rowcount==1;db.commit()
    after=db.execute("SELECT * FROM UP_Keys WHERE Section='internet' AND Name='Web_active' AND Idx=0").fetchone()
    expected=list(old[0]);expected[4]=1;assert tuple(expected)==after
    for name,rows in before.items():
        actual=db.execute('SELECT * FROM "'+name.replace('"','""')+'"').fetchall()
        assert actual==[tuple(expected) if name=='UP_Keys' and r==old[0] else r for r in rows]
    assert db.execute('PRAGMA integrity_check').fetchall()==[('ok',)]
    raw=db.serialize();db.close();stored=gzip.compress(raw,mtime=0);sidecar=encode_inf(raw,stored);assert verify_inf(raw,stored,sidecar)
    # Both native updater variants hardcode NAV/USER_DATA, independently of
    # the installed application profile. AUDIO_BT_256/USER_DATA is never read.
    dest=out/'NAV/USER_DATA/user_data/sqlite/up_config.sqlite';dest.parent.mkdir(parents=True);dest.write_bytes(stored);Path(str(dest)+'.inf').write_bytes(sidecar)
    restored=[]
    if a.all_live_databases:
        for original in sorted((ORIGINAL/'usb/SMEG_BACKUP').glob('*.sqlite')):
            if original.name=='up_config.sqlite':continue
            payload=original.read_bytes();validation=Path(str(original)+'.inf').read_bytes()
            assert verify_inf(gzip.decompress(payload),payload,validation)
            target=dest.with_name(original.name);target.write_bytes(payload);Path(str(target)+'.inf').write_bytes(validation)
            assert target.read_bytes()==original.read_bytes()
            restored.append(original.name)
        assert len(restored)==6
    # No other live database is shipped. The native update's restore/copy policy
    # must still be tested; host row preservation alone is not installation proof.
    log="UP_Keys: Section='internet', Name='Web_active', Idx=0, Type=2, IntValue:0 ->1\nAll other rows/columns identical to the verified original German backup.\n"
    (out.parent/'flag_changes.log').write_text(log)
    report={'emulator_only':True,'physical_car_approved':False,'native_update_completed':False,
            'persistent_boot_test_passed':False,'variant':a.variant,'database_change':log.strip(),
            'no_other_live_database_shipped':not a.all_live_databases,
            'other_database_payloads_byte_exact_originals':restored,
            'native_USER_DATA_source':'/bd0/SMEG_PLUS_UPG/NAV/USER_DATA',
            'USER_DATA_native_copy_and_restore_not_yet_verified':True,
            'profile_metadata_BIGQUICK_CRC32':hex(application_crc),
            'control_changes':update_controls(out),'contract':seal_contract(out)}
    report['changed_vendor_files']=[str(x.relative_to(out)) for x in out.rglob('*') if x.is_file() and (not(SOURCE/x.relative_to(out)).exists() or sha(x)!=sha(SOURCE/x.relative_to(out)))]
    for entry in original_manifest['files']:assert sha(ORIGINAL/'usb'/entry['path'])==entry['sha256']
    report['original_backup_files_verified']=len(original_manifest['files'])
    if a.image:report['virtual_USB']=create(out,a.image)
    (out.parent/'candidate-validation.json').write_text(json.dumps(report,indent=2)+'\n')
    (out.parent/'EMULATOR_ONLY_DO_NOT_INSTALL.txt').write_text('Native update and cold-reboot validation are incomplete. Do not install this candidate on the car.\n')
    print(json.dumps({'candidate':str(out),'changed_vendor_files':len(report['changed_vendor_files']),'physical_car_approved':False}))


if __name__=='__main__':main()
