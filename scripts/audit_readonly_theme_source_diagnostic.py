#!/usr/bin/env python3
"""Verify a completed source-only QEMU diagnostic and all stock containers."""
import hashlib,json,os,re,subprocess,tempfile
from pathlib import Path
from audit_warmlight_single_flag import read_snapshot,no_visible_writer
ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'artifacts/phase21/read-only-source-diagnostic-v1'
RUN=ROOT/'artifacts/phase8/usb-maintenance/runs/T22SOURCEDIAG01'
def main():
 out=BASE/'verification.json';assert not out.exists();meta=json.loads((BASE/'usb.json').read_text());result=json.loads((RUN/'result.json').read_text());assert result['returncode']==0 and result['wait_marker_seen']and result['native_memory_requested']
 text=subprocess.check_output(['mtype','-i',str(RUN/'usb.raw')+'@@1048576','::/USB_DIAG/RESULT.TXT'],env=dict(os.environ,MTOOLS_SKIP_CHECK='1'),text=True)
 assert 'CRC_TABLE_REFERENCE_MISMATCHES=0\n'in text and 'DIAGNOSTIC_COMPLETE status=0\n'in text
 blocks=re.findall(r'BEGIN path=(\S+) chunk=(\d+)[^\n]*\n(.*?)(?=BEGIN |DIAGNOSTIC_COMPLETE)',text,re.S);assert len(blocks)==6
 cases={r['path']:r for r in meta['source_cases']};checks=[]
 for path,chunk,body in blocks:
  case=cases[path];match=re.search(r'END bytes=(\d+) CRC32=([0-9a-f]+) FNV1A=([0-9a-f]+) ferror=(\d+) .*?fclose=(-?\d+).*?prefix_bytes=(\d+) prefix_bitwise_CRC32=([0-9a-f]+)',body)
  assert match,(path,body[-400:]);n,crc,fnv,err,closed,prefix,pcrc=match.groups()
  assert int(n)==case['bytes']and int(crc,16)==case['crc']and int(fnv,16)==case['fnv']and int(err)==0 and int(closed)==0 and int(prefix)==65536 and int(pcrc,16)==case['prefix_bitwise_CRC32']and 'SOURCE_MATCH=1'in body
  checks.append(dict(path=path,chunk=int(chunk),bytes=int(n),CRC32=crc,FNV1A=fnv,independent_prefix_CRC32_valid=True))
 no_visible_writer(RUN/'nand.raw')
 with tempfile.TemporaryDirectory()as td:
  snapshot=read_snapshot(RUN/'nand.raw',Path(td),'after',observe=True)
  assert len(snapshot['containers'])==3 and all(c['full_native_payload_exact']for c in snapshot['containers'])
  assert all(d['sqlite_integrity_and_INF_valid']for d in snapshot['databases'].values())
 source=ROOT/'emulation/usb_theme_source_diagnostic.c';assert hashlib.sha256(source.read_bytes()).hexdigest()==meta['source_sha256']
 imports={s.split()[-1]for s in meta['module_imports'].splitlines()if s.strip()};assert imports=={'errnoGet','fclose','ferror','fflush','fopen','fprintf','fread','mkdir','printf','sysClkRateGet','tickGet'}
 assert 'fopen(path, "rb")'in source.read_text()or'fopen(path,"rb")'in source.read_text()
 report=dict(scope='Native QEMU read-only diagnostic; physical read failure not reproduced here',image_sha256=meta['image_sha256'],source_sha256=meta['source_sha256'],native_test_complete=True,checks=checks,all_three_stock_application_and_theme_containers_exact=True,all_seven_databases_valid=True,NAND_write_APIs=False,configuration_setters=False,physical_car_tested=False)
 (BASE/'qemu-diagnostic-result.txt').write_text(text);out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
