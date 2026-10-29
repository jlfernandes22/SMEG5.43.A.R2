#!/usr/bin/env python3
"""Audit stopped sandbox NAND resource writes and all saved database changes."""
import argparse
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import subprocess
import struct
import tempfile
import zlib

from audit_warmlight_single_flag import read_snapshot, no_visible_writer
from audit_persistent_candidate import native_payload
from theme_resource_format import native_bank
from audit_usb_single_key import read_db, difference

ROOT = Path(__file__).resolve().parents[1]


def require(value, message):
    if not value:
        raise ValueError(message)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run', type=Path, required=True)
    p.add_argument('--probe', type=Path, required=True)
    p.add_argument('--after', type=Path)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    run, probe = a.run.resolve(), a.probe.resolve()
    after = a.after.resolve() if a.after else run/'nand.raw'
    require(run.is_relative_to(ROOT/'artifacts') and probe.is_relative_to(ROOT/'artifacts/phase20')
            and after.is_relative_to(ROOT/'artifacts') and not after.is_symlink(), 'Workspace artifacts required')
    require(not a.output.exists(), 'Preserve prior audits')
    no_visible_writer(after)
    metadata = json.loads((probe/'usb.json').read_text())
    allowed_flags=['display.Harm_'+str(uid)+'.0=1'for uid in (1,2,3,4,7,8)]
    require(metadata['emulator_only'] and not metadata['application_or_BSP_writes']
            and (not metadata['configuration_setters'] or
                 metadata.get('complete_stock_to_eight_theme_installer') and
                 metadata.get('requested_configuration_flags')==allowed_flags and
                 not metadata['replacement_databases']), 'Unexpected writer scope')
    resources = []
    with after.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        for b in metadata['banks']:
            source = probe/f"bank{b['bank']}.bin"
            require(hashlib.sha256(source.read_bytes()).hexdigest() == b['sha256'], 'Candidate resource changed')
            native = native_bank(source.read_bytes(), Path(str(source)+'.inf').read_bytes())
            start = {1: 0x2dc0000, 2: 0x4f60000}[b['bank']]
            actual = b''.join(mm[((start+off)//2048)*2112:((start+off)//2048)*2112+min(2048,len(native)-off)]
                              for off in range(0, len(native), 2048))
            entries=[]
            count=struct.unpack_from('>I',native,2048+32)[0]
            defined=bytearray(len(native))
            defined[:168]=b'\1'*168
            defined[2048:2048+36+count*216]=b'\1'*(36+count*216)
            for index in range(count):
                record=native[2084+index*216:2084+(index+1)*216]
                uid,page,size,crc=struct.unpack_from('>IIII',record,200)
                lo=page*2048;hi=lo+size
                payload=actual[lo:hi]
                entries.append(dict(name=record[:196].split(b'\0')[0].decode('ascii'),uid=uid,
                                    compressed_bytes=size,source_payload_byte_exact=payload==native[lo:hi],
                                    stored_CRC32_valid=len(payload)==size and zlib.crc32(payload)==crc))
                defined[lo:hi]=b'\1'*size
            ignored_padding_changes=sum(x!=y for i,(x,y)in enumerate(zip(actual,native))if not defined[i])
            defined_changes=sum(x!=y for i,(x,y)in enumerate(zip(actual,native))if defined[i])
            resources.append(dict(bank=b['bank'], native_payload_bytes=len(native),
                                  expected_sha256=hashlib.sha256(native).hexdigest(),
                                  actual_sha256=hashlib.sha256(actual).hexdigest(),
                                  full_native_payload_byte_exact=actual == native,
                                  defined_resource_bytes_changed=defined_changes,
                                  all_defined_resource_bytes_exact=len(actual)==len(native) and defined_changes==0,
                                  preheader_byte_exact=actual[:168]==native[:168],
                                  directory_byte_exact=actual[2048:2048+36+count*216]==native[2048:2048+36+count*216],
                                  entries=entries,undefined_padding_bytes_changed=ignored_padding_changes))
    with tempfile.TemporaryDirectory(prefix='smeg-resource-audit-') as temp:
        temp = Path(temp)
        snap = read_snapshot(after, temp, 'after', observe=True)
        log = temp/'install.txt'
        subprocess.run(['mcopy', '-i', str(run/'usb.raw')+'@@1048576',
                        '::/SMEG_BACKUP/theme-install.txt', str(log)], check=True,
                       capture_output=True, env=dict(os.environ, MTOOLS_SKIP_CHECK='1'))
        native_log = log.read_text()
        dbs, unexpected = [], []
        for name, data in snap['databases'].items():
            stored, inf = temp/('before-'+name), temp/('before-'+name+'.inf')
            for dest, member in [(stored,name),(inf,name+'.inf')]:
                subprocess.run(['mcopy', '-i', str(run/'usb.raw')+'@@1048576',
                                '::/SMEG_BACKUP/'+member, str(dest)], check=True,
                               capture_output=True, env=dict(os.environ, MTOOLS_SKIP_CHECK='1'))
            before = read_db(stored.read_bytes(), inf.read_bytes())
            require(data.get('sqlite_integrity_and_INF_valid'), 'Invalid post-install database '+name)
            diff = difference(before, data['rows'])
            dbs.append(dict(name=name, native_INF_and_integrity_valid=True,
                            pre_USB_to_after_differences=diff))
            for change in diff:
                if change.get('schema_changed') or change['table'] != 'UP_Keys':
                    unexpected.append(dict(database=name, change=change)); continue
                for row in change.get('removed',[]) + change.get('added',[]):
                    theme = ((name == 'up_config.sqlite' and row['Section'] == 'display' and re.fullmatch(r'Harm_\d+',row['Name']))
                             or (name == 'up_config.sqlite' and row['Section'] == 'upgrade' and row['Name'] == 'HarmoniesChecked')
                             or (name == 'up_common.sqlite' and row['Section'] == 'supervisor'
                                 and re.fullmatch(r'harmony\d+|harm\d+_(offset_area|number)',row['Name'])))
                    ordinary=(name=='up_common.sqlite'and(row['Section'],row['Name'],row['Idx'])in{
                        ('Desktop_services','Last_application_ID',0),('Desktop_services','Last_position',0),
                        ('supervisor','Last_Source',0),('supervisor','Last_Source_Priority',0),
                        ('USB','VENDOR_STRING',0),('USB','PRODUCT_STRING',0),
                        ('USB','Block_number',0),('USB','Block_free_number',0)})
                    if not theme and not ordinary:
                        unexpected.append(dict(database=name, row=row))
        selected = []
        for name in ['up_config.sqlite','up_common.sqlite']:
            for row in snap['databases'][name]['rows']['UP_Keys']['rows']:
                if ((row['Section']=='display' and row['Name'].startswith('Harm_'))
                    or (row['Section']=='supervisor' and re.fullmatch(r'harmony\d+|harm\d+_offset_area',row['Name']))
                    or (row['Section']=='display_configuration' and row['Name']=='Display_Color')):
                    selected.append(dict(database=name, **{k:row[k] for k in ['Section','Name','Idx','IntValue','StringValue']}))
    app = next(c for c in snap['containers'] if 'f_BigQuick.bin' in c['path'])
    unmodified = [c for c in snap['containers'] if any(f'BigHarmony_{g}/' in c['path'] for g in (4,5)
                                                   if g-3 not in {b['bank'] for b in metadata['banks']})]
    result = dict(scope='Stopped QEMU images only; no physical device access',
                  after=str(after), NAND_sha256=snap['sha256'], native_log=native_log,
                  native_install_success='FINISHED native USB resource installation' in native_log
                                         and 'INSTALL_RESULT status=0' in native_log,
                  resources=resources, original_application_byte_exact=app['full_native_payload_exact'],
                  unmodified_banks_byte_exact=all(c['full_native_payload_exact'] for c in unmodified),
                  all_seven_databases_valid=True, databases=dbs,
                  all_database_rows_unchanged=all(not d['pre_USB_to_after_differences'] for d in dbs),
                  non_theme_setting_differences=unexpected,
                  native_Harmony_ini_hex=snap['Harmony.ini'].hex(), theme_rows=selected,
                  UI_theme_selection_verified=False)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:result[k] for k in ['native_install_success','resources','original_application_byte_exact',
                                         'unmodified_banks_byte_exact','all_database_rows_unchanged']},indent=2))
    print('Non-theme differences:',len(unexpected))


if __name__ == '__main__':
    main()
