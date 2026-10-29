#!/usr/bin/env python3
"""Stage original vendor updater + validated SQLite USER_DATA overlay for QEMU.
This does not create a vendor signature, patch code, or use the FLYING loader.
Only regular files are used. Source firmware and the original contract stay intact.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import struct
import subprocess
import sys
import zlib

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT/'scripts'))
from smeg_db_inf import crc16, encode_inf, verify_inf


def hash_file(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        while b := f.read(1024*1024): h.update(b)
    return h.hexdigest()


def validate_contract(package):
    # Reuse the local read-only decoder. Key material stays in process memory.
    sys.path.insert(0, str(ROOT/'sources/smeg-plus-patches/tools'))
    from patch_contract import find_keys, inflate, load_contract, resolve
    keys = find_keys(inflate(package/'NAV/AppBin/f_BigQuick.bin'))
    _, records, _ = load_contract(package/'contract.dat', keys)
    errors, paths = [], []
    for rec in records:
        name = rec[:rec.index(b'\0')].decode(); paths.append(name)
        path = Path(resolve(package, name))
        # FAT32 lookup is case-insensitive; the extracted host tree is not.
        if not path.exists():
            current = package
            relative = path.relative_to(package)
            for part in relative.parts:
                matches = [x for x in current.iterdir() if x.name.casefold() == part.casefold()] if current.is_dir() else []
                if len(matches) != 1: break
                current = matches[0]
            else: path = current
        if not path.is_file(): errors.append({'path':name,'error':'missing'}); continue
        kind = rec[63]
        if kind == 1:
            actual, expected = path.stat().st_size, int.from_bytes(rec[72:76],'big')
        elif kind == 2:
            crc = 0
            with path.open('rb') as f:
                while data := f.read(1024*1024): crc = zlib.crc32(data,crc)
            actual, expected = crc & 0xffffffff, int.from_bytes(rec[72:76],'big')
        elif kind == 3:
            size, offset = struct.unpack_from('>II',rec,64)
            with path.open('rb') as f: f.seek(offset); actual = f.read(size)
            expected = rec[72:72+size]
        else: raise ValueError('Unknown contract record type')
        if actual != expected: errors.append({'path':name,'error':'value mismatch'})
    if errors: raise ValueError(json.dumps(errors))
    return {'records_checked':len(records),'all_original_contract_records_match':True,
            'USER_DATA_overlay_covered_by_original_contract':any('/USER_DATA/' in p for p in paths),
            'key_material_written_or_logged':False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,default=ROOT/'artifacts/phase2/package/SMEG_PLUS_UPG')
    p.add_argument('--databases',type=Path,default=ROOT/'artifacts/phase4/variants/main_feedback/deploy/user_data/sqlite')
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--image',type=Path)
    a = p.parse_args()
    if a.output.exists() or (a.image and a.image.exists()): p.error('Output already exists; preserve prior runs')
    if str(a.output.resolve()).startswith('/dev/') or (a.image and str(a.image.resolve()).startswith('/dev/')):
        p.error('Only regular sandbox paths are supported')
    if a.output.name != 'SMEG_PLUS_UPG': p.error('Updater requires this exact folder name')
    a.output.parent.mkdir(parents=True,exist_ok=True)
    # The destination must be a new independent copy, never hard links to vendor files.
    subprocess.run(['cp','--reflink=auto','-a',str(a.source),str(a.output)],check=True)
    report = {'physical_car_access':False,'package_type':'Original vendor package plus USER_DATA overlay',
              'cryptographic_vendor_signature_generated':False,'FLYING_loader_used':False,
              'vendor_code_modified':False,'databases':[],
              'eco_default_off':'Not established by SQLite; emulator ECU fixture is separate'}
    plugin = (a.output/'UpgPlugin.out').read_bytes()
    inf = (a.output/'UpgPlugin.out.inf').read_bytes()
    assert int(inf[:4],16) == crc16(inf[4:]) and int(inf[4:8],16) == crc16(plugin)
    target = a.output/'NAV/USER_DATA/user_data/sqlite'; target.mkdir(parents=True)
    for name in ['up_config.sqlite','config_options.sqlite']:
        source = (a.databases/name).read_bytes()
        raw = gzip.decompress(source) if source[:2] == b'\x1f\x8b' else source
        c = sqlite3.connect(':memory:'); c.deserialize(raw); c.execute('PRAGMA trusted_schema=OFF')
        if c.execute('PRAGMA integrity_check').fetchall() != [('ok',)]: raise ValueError('Invalid SQLite database')
        flags = c.execute('SELECT name,value FROM sw_option ORDER BY name').fetchall() if name=='config_options.sqlite' else []
        c.close(); stored=gzip.compress(raw,mtime=0); sidecar=encode_inf(raw,stored)
        verify_inf(raw,stored,sidecar)
        (target/name).write_bytes(stored); (target/(name+'.inf')).write_bytes(sidecar)
        report['databases'].append({'path':str((target/name).relative_to(a.output)),
            'sha256':hashlib.sha256(stored).hexdigest(),'raw_sha256':hashlib.sha256(raw).hexdigest(),
            'sqlite_integrity':'ok','native_gzip_inf':sidecar.decode(),'sw_options':flags})
    assert hash_file(a.source/'contract.dat') == hash_file(a.output/'contract.dat')
    report['contract']=validate_contract(a.output)
    report['contract']['original_vendor_contract_unchanged']=True
    if a.image:
        a.image.parent.mkdir(parents=True,exist_ok=True)
        size=2*1024**3; first=2048; sectors=size//512-first
        mbr=bytearray(512);mbr[446:462]=struct.pack('<B3sB3sII',0,b'\xfe\xff\xff',0x0c,b'\xfe\xff\xff',first,sectors);mbr[510:512]=b'\x55\xaa'
        with a.image.open('xb') as f: f.truncate(size);f.write(mbr)
        subprocess.run(['mkfs.vfat','-F','32','-n','SMEG_UPDATE','--offset',str(first),str(a.image),str(sectors//2)],check=True,capture_output=True)
        disk=str(a.image.resolve())+'@@'+str(first*512)
        subprocess.run(['mcopy','-s','-i',disk,str(a.output),'::/'],check=True,capture_output=True,env=dict(os.environ,MTOOLS_SKIP_CHECK='1'))
        report['usb']={'image':str(a.image),'format':'MBR/FAT32','bytes':size,'partition_offset':first*512}
    (a.output.parent/'package-validation.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__': main()
