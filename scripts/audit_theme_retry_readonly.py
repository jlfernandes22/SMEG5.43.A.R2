#!/usr/bin/env python3
"""Bind exact read-only USB bytes to native read, UI, and preservation evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from audit_warmlight_single_flag import read_snapshot,no_visible_writer
from audit_usb_single_key import difference
from prepare_retry_readonly_usb import (
    artifact_directory, safe_file, source_byte_progress, validate_progress_evidence,
)
ROOT=Path(__file__).resolve().parents[1]
def sha(p):
    with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--probe',type=Path,required=True);p.add_argument('--run',type=Path,required=True);p.add_argument('--failure-run',type=Path,required=True)
    p.add_argument('--ui-proof',type=Path,default=ROOT/'artifacts/phase21/native-progress-completion-ui-proof.json')
    p.add_argument('--ui-review',type=Path,default=ROOT/'artifacts/phase21/combined-readonly-ui-review.json')
    a=p.parse_args();base=artifact_directory(a.probe);run=artifact_directory(a.run);bad=artifact_directory(a.failure_run)
    out=base/'verification.json';assert not out.exists()
    m=json.loads((base/'usb.json').read_text());assert sha(base/'usb.raw')==m['image_sha256']
    for n,h in m['source_sha256'].items():assert sha(base/n)==h
    for n in ['usb_theme_retry_readonly.c','theme_source_verify.h','theme_install_progress.h']:assert sha(ROOT/'emulation'/n)==m['source_sha256'][n]
    evidence=[]
    def bind(path):
        path=safe_file(path).resolve()
        if not any(r['path']==str(path)for r in evidence):evidence.append(dict(path=str(path),sha256=sha(path)))
    ui_path=safe_file(a.ui_proof).resolve();ui=json.loads(ui_path.read_text());bind(ui_path);bind(ui['native_ID_proof'])
    for field in ['native_progress_API_proof','controlled_progress_demo_proof']:
        if field in ui:bind(ui[field])
    assert ui['all_tests_pass'] and ui['shared_helper_sha256']==m['source_sha256']['theme_install_progress.h']
    assert {t['name']for t in ui['tests']}=={'success','failure'}
    for t in ui['tests']:
        assert t['native_popup_reached_visible_state2']and t['original_text_restored']and t['visual_review']['reviewed']
        if m.get('determinate_progress')is True:
            assert t.get('native_BCM_progress_unchanged')is True
            assert 'PROGRESS_RESTORED client_unchanged=1'in t['trace']
        assert sha(Path(t['screenshot']))==t['screenshot_sha256'];bind(t['screenshot']);bind(Path(t['run'])/'result.json');bind(t['source_manifest'])
    progress_rows=[]
    if m.get('determinate_progress')is True:
        progress_rows=validate_progress_evidence(ui)
        for row in progress_rows:bind(row['screenshot'])
    review_path=safe_file(a.ui_review).resolve();review=json.loads(review_path.read_text());bind(review_path)
    for folder in [run,bad]:
        r=next(r for r in review['reviews']if r['run']==folder.name)
        assert r['native_popup_visible']and Path(r['screenshot'])==folder/'after-usb.png'
        assert sha(Path(r['screenshot']))==r['sha256']
    env=dict(os.environ,MTOOLS_SKIP_CHECK='1')
    def receipt(folder,name):return subprocess.check_output(['mtype','-i',str(folder/'usb.raw')+'@@1048576','::/'+name],text=True,env=env)
    checks={};native_progress=[]
    for folder,expected in [(run,0),(bad,-63)]:
        result=json.loads((folder/'result.json').read_text());assert result['returncode']==0 and result['wait_marker_seen']and result['native_memory_requested']
        text=receipt(folder,'READCHECK.TXT');state=receipt(folder,'THEME_STATUS.TXT');trace=receipt(folder,'UI_TRACE.TXT')
        assert f'READ_ONLY_CHECK_RESULT status={expected}\n'in text
        assert state.splitlines()[0]==('DONE'if expected==0 else'FAILED')
        assert 'COMPLETE_ACTIVATION_WAITED'in trace and re.search(r'COMPLETE_ACTIVATION_WAITED .*complete=2',trace)
        headers=re.findall(r'STOCK_PREHEADER bank=(\d+) status=(-?\d+) hash=([0-9a-f]+) expected=([0-9a-f]+)',text)
        assert len(headers)==2 and all(s=='0'and h==e for _,s,h,e in headers)
        pattern=r'SOURCE_CHECK path=(\S+) attempt=(\d+) opened=(\d+) bytes=(\d+) expected_bytes=(\d+) CRC32=([0-9a-f]+) expected_crc=([0-9a-f]+) ferror=(-?\d+) fclose=(-?\d+) errno=([0-9a-f]+) consecutive=(\d+) buffer=(\S+) MOD64=(\d+)'
        rows=re.findall(pattern,text);assert rows and all(r[-1]=='0'for r in rows)
        if expected==0 and m.get('determinate_progress')is True:
            native_progress=source_byte_progress(text)
            validate_progress_evidence(ui,source_rows=native_progress,run=run)
        if expected==0:
            for bank in [1,2]:
                values=[r for r in rows if r[0]==f'/bd0/THEME_TEST/bank{bank}.bin'];assert 2<=len(values)<=3
                assert [int(r[1])for r in values]==list(range(1,len(values)+1))
                for r,n in zip(values[-2:],[1,2]):assert r[2]=='1'and r[3]==r[4]and r[5]==r[6]and r[7]=='0'and r[8]=='0'and int(r[10])==n
        else:assert len(rows)==3 and all(r[3]=='4096'and r[10]=='0'for r in rows)
        saved=base/('qemu-readchecks.txt'if expected==0 else'qemu-failure-readchecks.txt');saved.write_text(text);bind(saved)
        bind(folder/'result.json');bind(folder/'after-usb.png')
        if(folder/'checkpoints.json').exists():bind(folder/'checkpoints.json')
        checks[str(folder)]=dict(expected_status=expected,receipt=state,trace=trace,attempts=len(rows))
    # The negative image contains the exact same executable/validation files.
    for n in ['FLYING/readcheck.out','FLYING/readcheck.out.inf','FLYING/doctor_smeg_plus_i.inf']:
        original=subprocess.check_output(['mtype','-i',str(base/'usb.raw')+'@@1048576','::/'+n],env=env)
        for folder in [run,bad]:
            actual=subprocess.check_output(['mtype','-i',str(folder/'usb.raw')+'@@1048576','::/'+n],env=env)
            assert original==actual
    seed=ROOT/'artifacts/phase20/latest-car-seed.raw'
    allowed={('Desktop_services','Last_application_ID',0),('Desktop_services','Last_position',0),('supervisor','Last_Source',0),('supervisor','Last_Source_Priority',0),('USB','VENDOR_STRING',0),('USB','PRODUCT_STRING',0),('USB','Block_number',0),('USB','Block_free_number',0)}
    snapshots=[]
    with tempfile.TemporaryDirectory()as td:
        temp=Path(td);before=read_snapshot(seed,temp,'before',observe=True)
        for label,folder in [('success',run),('failure',bad)]:
            no_visible_writer(folder/'nand.raw');snap=read_snapshot(folder/'nand.raw',temp,label,observe=True)
            assert len(snap['containers'])==3 and all(c['full_native_payload_exact']for c in snap['containers'])
            assert len(snap['databases'])==7 and all(d['sqlite_integrity_and_INF_valid']for d in snap['databases'].values())
            assert snap['Harmony.ini']==before['Harmony.ini']
            diffs=[];unexpected=[]
            for n,db in snap['databases'].items():
                changes=difference(before['databases'][n]['rows'],db['rows'])
                for change in changes:
                    diffs.append(dict(database=n,change=change))
                    if change.get('schema_changed')or change['table']!='UP_Keys':unexpected.append(diffs[-1]);continue
                    for row in change['removed']+change['added']:
                        if n!='up_common.sqlite'or(row['Section'],row['Name'],row['Idx'])not in allowed:unexpected.append(diffs[-1]);break
            snapshots.append(dict(label=label,containers=snap['containers'],database_differences=diffs,unexpected_preference_changes=unexpected))
    snapshot_path=base/'preservation-audit.json';snapshot_path.write_text(json.dumps(snapshots,indent=2)+'\n');bind(snapshot_path)
    assert all(not r['unexpected_preference_changes']for r in snapshots),'Inspect preservation-audit.json'
    report=dict(native_test_complete=True,both_bank_checks_pass=True,native_UI_success_verified=True,native_UI_failure_verified=True,
        all_three_stock_application_and_theme_containers_exact=True,all_seven_databases_valid=True,
        unrelated_preferences_unchanged=True,physical_car_tested=False,read_only_physical_test_only=True,
        image_sha256=m['image_sha256'],source_sha256=m['source_sha256'],evidence=evidence,runs=checks,
        limitation='Native QEMU evidence only; no physical installer approval. Stock updater success text is reused for this read-only check.')
    if progress_rows:report.update(real_progress_verified=True,progress_evidence=progress_rows,
                                  native_source_byte_progress_verified=True,source_progress=native_progress)
    out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items()if k not in ['runs','evidence','source_sha256']}))
if __name__=='__main__':main()
