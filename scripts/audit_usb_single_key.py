#!/usr/bin/env python3
"""Compare native USB before-save backups with a stopped emulator NAND only."""
import argparse
import gzip
import hashlib
import json
import mmap
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'emulation'))
from inject_volume import discover,mappings,bpb,extract
from smeg_db_inf import verify_inf

ROOT=Path(__file__).resolve().parents[1]
ORIGINAL=ROOT/'artifacts/live_car_backup/2026-10-27-native-usb'
ENV=dict(os.environ,MTOOLS_SKIP_CHECK='1')


def run(*cmd):return subprocess.run(cmd,check=True,capture_output=True,env=ENV)


def read_db(stored,sidecar=None):
    raw=gzip.decompress(stored) if stored[:2]==b'\x1f\x8b' else stored
    if sidecar is not None:assert verify_inf(raw,stored,sidecar),'Native checksum mismatch'
    db=sqlite3.connect(':memory:');db.deserialize(raw)
    assert db.execute('PRAGMA integrity_check').fetchall()==[('ok',)]
    result={}
    def value(x):return {'blob_hex':x.hex()} if isinstance(x,bytes) else x
    for (table,sql) in db.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"):
        columns=[r[1]for r in db.execute('PRAGMA table_info("'+table.replace('"','""')+'")')]
        result[table]={'sql':sql,'columns':columns,'rows':[
            {c:value(x)for c,x in zip(columns,row)}for row in db.execute('SELECT * FROM "'+table.replace('"','""')+'"')]}
    db.close();return result


def difference(before,after):
    result=[]
    for table in sorted(set(before)|set(after)):
        b,a=before.get(table),after.get(table)
        if b is None or a is None or b['sql']!=a['sql']:
            result.append({'table':table,'schema_changed':True});continue
        removed=set(json.dumps(r,sort_keys=True)for r in b['rows'])-set(json.dumps(r,sort_keys=True)for r in a['rows'])
        added=set(json.dumps(r,sort_keys=True)for r in a['rows'])-set(json.dumps(r,sort_keys=True)for r in b['rows'])
        if removed or added:
            result.append({'table':table,'removed':[json.loads(s)for s in sorted(removed)],
                           'added':[json.loads(s)for s in sorted(added)]})
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--control',action='store_true',help='Audit the read-only exporter control')
    p.add_argument('--portal',action='store_true',help='Audit the native portal-location string test')
    p.add_argument('--portal-value',default='/bd0/SMEG_CAP/index.html',help='Expected native portal value when using --portal')
    p.add_argument('--include-generated',action='store_true',help='Also compare the generated config/manager/browser databases backed up by the native exporter')
    p.add_argument('--web-already-enabled',action='store_true',help='Expect the native Web setter to observe 1 and make no setter request')
    p.add_argument('--before-nand',type=Path,help='Use this stopped original emulator image instead of a guest USB before-copy')
    a=p.parse_args()
    root=a.run.resolve();output=a.output.resolve()
    assert root.is_relative_to(ROOT/'artifacts') and output.is_relative_to(ROOT/'artifacts')
    report={'physical_device_access':False,'native_module_writes':('none' if a.control else 'one-key UP API request; full original files backed up first'),
            'scope':'Stopped disposable emulator images only','databases':[]}
    if a.before_nand:
        assert a.before_nand.is_file() and a.before_nand.resolve().is_relative_to(ROOT/'artifacts')
        report['baseline_nand']=str(a.before_nand.resolve())
        report['native_module_writes']='Compare all stored data; runtime probe does not call stored preference setters'
        with a.before_nand.open('rb')as baseline:report['baseline_nand_sha256']=hashlib.file_digest(baseline,'sha256').hexdigest()
    with tempfile.TemporaryDirectory(prefix='smeg-usb-audit-')as tmp:
        tmp=Path(tmp)
        with (root/'nand.raw').open('rb')as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)as mm:
            selected=[(k,h)for k,h in discover(mm).items()if min(x['page']for x in h)==103168]
            assert len(selected)==1
            k,h=selected[0];latest,_=mappings(mm,h,k[2]);fs=bpb(mm,latest)
            fat=tmp/'after.fat';fat.write_bytes(extract(mm,latest,fs['sectors']))
        before_fat=None
        if a.before_nand:
            with a.before_nand.open('rb')as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)as mm:
                choices=[(k,h)for k,h in discover(mm).items()if min(x['page']for x in h)==103168]
                assert len(choices)==1
                k,h=choices[0];latest,_=mappings(mm,h,k[2]);fs=bpb(mm,latest)
                before_fat=tmp/'before.fat';before_fat.write_bytes(extract(mm,latest,fs['sectors']))
        for source in sorted((ORIGINAL/'usb/SMEG_BACKUP').glob('*.sqlite')):
            name=source.name;before_files={};after_files={}
            for suffix in ('','.inf'):
                before=tmp/('before-'+name+suffix);after=tmp/('after-'+name+suffix)
                run('mcopy','-i',str(before_fat)if before_fat else str(root/'usb.raw')+'@@1048576',
                    ('::/user_data/sqlite/'if before_fat else '::/SMEG_BACKUP/')+name+suffix,str(before))
                run('mcopy','-i',str(fat),'::/user_data/sqlite/'+name+suffix,str(after))
                before_files[suffix]=before.read_bytes();after_files[suffix]=after.read_bytes()
            before=read_db(before_files[''],before_files['.inf']);after=read_db(after_files[''],after_files['.inf'])
            original=read_db(source.read_bytes(),Path(str(source)+'.inf').read_bytes())
            report['databases'].append({'name':name,'native_checksums_valid':True,'sqlite_integrity':'ok',
                'pre_to_post_usb':difference(before,after),'original_to_pre_usb':difference(original,before)})
        if not a.before_nand:
            log=run('mtype','-i',str(root/'usb.raw')+'@@1048576',
                    '::/SMEG_BACKUP/'+('COMPLETE.txt' if a.control else 'change.txt')).stdout.decode()
            report['native_module_log']=log
            assert ('Export finished' if a.control else 'AFTER internet.URL_PSA_portal='+a.portal_value if a.portal else
                    'UNCHANGED already enabled; setter not called' if a.web_already_enabled else 'AFTER internet.Web_active.0=1') in log
        if a.include_generated:
            report['generated_databases']=[]
            for name in ['config.sqlite','db_manager.sqlite','connectivity.sqlite','desktopServices.sqlite','browser.sqlite','versions.sqlite']:
                before=tmp/('generated-before-'+name);after=tmp/('generated-after-'+name)
                b=subprocess.run(['mcopy','-i',str(before_fat)if before_fat else str(root/'usb.raw')+'@@1048576',
                    ('::/user_data/sqlite/'if before_fat else '::/SMEG_BACKUP/')+name,str(before)],capture_output=True,env=ENV)
                if b.returncode:continue
                c=subprocess.run(['mcopy','-i',str(fat),'::/user_data/sqlite/'+name,str(after)],capture_output=True,env=ENV)
                if c.returncode:
                    report['generated_databases'].append({'name':name,'after_missing':True});continue
                report['generated_databases'].append({'name':name,'sqlite_integrity':'ok',
                    'pre_to_post_usb':difference(read_db(before.read_bytes()),read_db(after.read_bytes()))})
    manifest=json.loads((ORIGINAL/'copy-manifest.json').read_text())
    bad=[e['path']for e in manifest['files']if hashlib.sha256((ORIGINAL/'usb'/e['path']).read_bytes()).hexdigest()!=e['sha256']]
    report['original_backup_files_verified']=len(manifest['files']);report['original_backup_mismatches']=bad
    assert not bad
    if a.before_nand:
        with a.before_nand.open('rb')as baseline:assert hashlib.file_digest(baseline,'sha256').hexdigest()==report['baseline_nand_sha256']
    output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'output':str(output),'valid_databases':len(report['databases']),
        'changed_after_usb':[{ 'database':d['name'],'tables':[x['table']for x in d['pre_to_post_usb']]}for d in report['databases']if d['pre_to_post_usb']],
        'original_backup_unchanged':True}))


if __name__=='__main__':main()
