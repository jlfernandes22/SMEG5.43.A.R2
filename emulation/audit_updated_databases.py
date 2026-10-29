#!/usr/bin/env python3
"""Compare a stopped/snapshotted emulator USER_DATA volume with target DB flags."""
import argparse
import gzip
import hashlib
import json
import mmap
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
from inject_volume import discover, mappings, bpb, extract


def inspect(data, name):
    raw=gzip.decompress(data) if data[:2]==b'\x1f\x8b' else data
    c=sqlite3.connect(':memory:');c.deserialize(raw);c.execute('PRAGMA trusted_schema=OFF')
    if c.execute('PRAGMA integrity_check').fetchall()!=[('ok',)]:raise ValueError('SQLite integrity failure')
    if name=='config_options.sqlite':
        rows=c.execute("SELECT name,value FROM sw_option WHERE name IN ('SW_OPTION_INTERNET','SW_OPTION_SMARTAPPS','SW_OPTION_BT_DUN') ORDER BY name").fetchall()
    else:
        rows=c.execute("SELECT Section,Name,Idx,IntValue FROM UP_Keys WHERE Section='internet' AND Name IN ('Smartapps','Wifi_active') ORDER BY Name,Idx").fetchall()
    c.close()
    return {'sha256':hashlib.sha256(data).hexdigest(),'raw_sha256':hashlib.sha256(raw).hexdigest(),'flags':rows,'integrity':'ok'}


p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--nand',type=Path,required=True)
p.add_argument('--expected',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args()
report={'physical_car_access':False,'nand':str(a.nand),'source':'Read-only offline NAND/VBF/FAT reconstruction','databases':{}}
with tempfile.TemporaryDirectory(prefix='smeg-update-audit-')as d:
    d=Path(d)
    with a.nand.open('rb')as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)as mm:
        chosen=[(k,h)for k,h in discover(mm).items()if min(x['page']for x in h)==220032]
        if len(chosen)!=1:raise ValueError('USER_DATA volume missing or ambiguous')
        key,headers=chosen[0];latest,_=mappings(mm,headers,key[2]);fs=bpb(mm,latest)
        fat=d/'user.fat';fat.write_bytes(extract(mm,latest,fs['sectors']))
    for name in ['up_config.sqlite','config_options.sqlite']:
        dest=d/name
        subprocess.run(['mcopy','-i',str(fat),'::/user_data/sqlite/'+name,str(dest)],check=True,capture_output=True,env=dict(os.environ,MTOOLS_SKIP_CHECK='1'))
        actual=inspect(dest.read_bytes(),name);expected=inspect((a.expected/name).read_bytes(),name)
        report['databases'][name]={'actual':actual,'expected':expected,'target_flags_match':actual['flags']==expected['flags']}
report['all_target_flags_match']=all(x['target_flags_match']for x in report['databases'].values())
report['update_success_claim_allowed']=report['all_target_flags_match']
a.output.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
