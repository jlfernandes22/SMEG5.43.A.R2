#!/usr/bin/env python3
"""Validate the extracted-checker read-only probe before any physical preparation."""
import hashlib,json,os,re,subprocess,tempfile
from pathlib import Path
from audit_warmlight_single_flag import read_snapshot,no_visible_writer
ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'artifacts/phase21/original-checker-readonly-v3';RUN=ROOT/'artifacts/phase8/usb-maintenance/runs/T22ORIGCHECK03'
def main():
 out=BASE/'verification.json';assert not out.exists();m=json.loads((BASE/'usb.json').read_text());r=json.loads((RUN/'result.json').read_text());assert r['returncode']==0 and r['wait_marker_seen']and r['native_memory_requested']
 s=subprocess.check_output(['mtype','-i',str(RUN/'usb.raw')+'@@1048576','::/CKDIAG/RESULT.TXT'],env=dict(os.environ,MTOOLS_SKIP_CHECK='1'),text=True);assert'ABORT'not in s and'ORIGINAL_CHECKER_PROBE_COMPLETE'in s
 assert'ORIGINAL_BEFORE_HEADER_READS status=0'in s and'ORIGINAL_AFTER_HEADER_READS status=0'in s
 assert'LEGACY_BUFFER_GUARD_CHANGED=0'in s and s.count('guard_changed=0')==2
 modes=re.findall(r'(LEGACY_BUFFER|ALIGNED_BUFFER)=[0-9a-f]+ MOD64=(\d+)',s);assert dict(modes)=={'LEGACY_BUFFER':'4','ALIGNED_BUFFER':'0'}
 headers=re.findall(r'NATIVE_HEADER bank=(\d+) status=(\d+) hash=([0-9a-f]+) expected=([0-9a-f]+) guard_changed_bytes=(\d+)',s);assert len(headers)==2 and all(status=='0'and h==expected and guard=='0'for bank,status,h,expected,guard in headers)
 companions=re.findall(r'COMPANION (\w+) bytes=(\d+) CRC32=([0-9a-f]+) FNV1A=([0-9a-f]+) ferror=(\d+) errno=([0-9a-f]+) fclose=(-?\d+) ticks=\d+ SOURCE_MATCH=(\d+)',s)
 assert len(companions)==2 and all(int(n)==30425088 and crc=='bd25fa15'and fnv=='1bf17166'and err=='0'and closed=='0'and match=='1'for name,n,crc,fnv,err,errno,closed,match in companions)
 assert re.search(r'CONSTANT_DATA_AFTER_NATIVE_READS=[0-9a-f]+ unchanged=1',s)
 no_visible_writer(RUN/'nand.raw')
 with tempfile.TemporaryDirectory()as td:
  snap=read_snapshot(RUN/'nand.raw',Path(td),'after',observe=True);assert len(snap['containers'])==3 and all(c['full_native_payload_exact']for c in snap['containers']);assert all(d['sqlite_integrity_and_INF_valid']for d in snap['databases'].values())
 source=ROOT/'emulation/usb_original_checker_probe.c';assert hashlib.sha256(source.read_bytes()).hexdigest()==m['source_sha256'];assert m['extracted_original_checker_instructions_byte_exact']and m['extracted_code_bytes']==332 and m['excluded_all_original_installer_code_except_checker']
 proof=dict(native_test_complete=True,original_checker_instruction_bytes_exact=True,original_checker_bytes=332,legacy_buffer_mod64=4,aligned_buffer_mod64=0,both_original_checker_calls_pass=True,both_companion_reads_pass=True,native_header_reads_bounded_in_QEMU=True,all_three_stock_application_and_theme_containers_exact=True,all_seven_databases_valid=True,source_sha256=m['source_sha256'],image_sha256=m['image_sha256'],NAND_write_APIs=False,configuration_setters=False,physical_car_tested=False,physical_cause_not_yet_proven=True)
 (BASE/'qemu-result.txt').write_text(s);out.write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps(proof,indent=2))
if __name__=='__main__':main()
