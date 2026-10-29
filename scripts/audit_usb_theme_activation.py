#!/usr/bin/env python3
"""Audit theme-only changes and preview file preservation in a stopped VM."""
import argparse
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import subprocess
import tempfile

from audit_warmlight_single_flag import read_snapshot, no_visible_writer
from audit_usb_single_key import read_db, difference
from inject_volume import discover, mappings, bpb, extract

ROOT=Path(__file__).resolve().parents[1]


def require(value,message):
    if not value:raise ValueError(message)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run',type=Path,required=True)
    p.add_argument('--after',type=Path)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();run=a.run.resolve();after=a.after.resolve() if a.after else run/'nand.raw'
    require(run.is_relative_to(ROOT/'artifacts') and after.is_relative_to(ROOT/'artifacts'),'Workspace inputs required')
    require(not a.output.exists(),'Preserve previous evidence')
    no_visible_writer(after)
    live=ROOT/'artifacts/phase19/theme-inventory/physical-return/usb/SMEG_BACKUP'
    env=dict(os.environ,MTOOLS_SKIP_CHECK='1')
    def run_cmd(*cmd):return subprocess.run(cmd,check=True,capture_output=True,env=env)
    with tempfile.TemporaryDirectory(prefix='smeg-theme-activation-audit-')as td:
        tmp=Path(td);snap=read_snapshot(after,tmp,'after',observe=True)
        dbs=[];unexpected=[];volatile=[];device_state=[]
        for name,record in snap['databases'].items():
            old=live/name
            original=read_db(old.read_bytes(),Path(str(old)+'.inf').read_bytes())
            require(record.get('sqlite_integrity_and_INF_valid'),'Invalid database '+name)
            diff=difference(original,record['rows'])
            dbs.append(dict(name=name,differences_from_latest_live_export=diff,integrity_and_INF_valid=True))
            for change in diff:
                if change.get('schema_changed') or change['table']!='UP_Keys':
                    unexpected.append(dict(database=name,change=change));continue
                before={(r['Section'],r['Name'],r['Idx']):r for r in change['removed']}
                added={(r['Section'],r['Name'],r['Idx']):r for r in change['added']}
                for key in before.keys()|added.keys():
                    section,k,idx=key
                    is_theme=(name=='up_config.sqlite' and ((section=='display' and re.fullmatch(r'Harm_\d+',k))
                              or (section=='upgrade' and k=='HarmoniesChecked')))
                    is_theme=bool(is_theme or (name=='up_common.sqlite' and section=='supervisor'
                                               and re.fullmatch(r'harmony\d+|harm\d+_(offset_area|number)',k)))
                    is_session=(name=='up_common.sqlite' and key in {
                        ('Desktop_services','Last_application_ID',0),('Desktop_services','Last_position',0),
                        ('supervisor','Last_Source',0),('supervisor','Last_Source_Priority',0)})
                    item=dict(database=name,key=list(key),before=before.get(key),after=added.get(key))
                    if is_theme:continue
                    if is_session:volatile.append(item)
                    elif name=='up_common.sqlite' and key in {
                        ('USB','VENDOR_STRING',0),('USB','PRODUCT_STRING',0),
                        ('USB','Block_number',0),('USB','Block_free_number',0)}:device_state.append(item)
                    else:unexpected.append(item)
        config=snap['databases']['up_config.sqlite']['rows']['UP_Keys']['rows']
        flags={r['Name']:r['IntValue'] for r in config if r['Section']=='display' and r['Idx']==0 and r['Name'].startswith('Harm_')}
        require(all(flags.get('Harm_'+str(i))==1 for i in [1,2,3,4,7,8,10,11]),'Incomplete active themes')
        common=snap['databases']['up_common.sqlite']['rows']['UP_Keys']['rows']
        selected=[r['IntValue'] for r in common if (r['Section'],r['Name'],r['Idx'])==('display_configuration','Display_Color',0)]
        names={r['Name']:r['StringValue'] for r in common if r['Section']=='supervisor' and re.fullmatch(r'harmony\d+',r['Name'])}
        system=tmp/'SYSTEM.fat'
        with after.open('rb')as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)as mm:
            choices=[(k,h) for k,h in discover(mm).items() if min(x['page']for x in h)==59072]
            require(len(choices)==1,'SYSTEM volume ambiguous')
            k,h=choices[0];latest,_=mappings(mm,h,k[2]);fs=bpb(mm,latest)
            system.write_bytes(extract(mm,latest,fs['sectors']))
        previews=[]
        for uid in [1,2,3,4,7,8]:
            target=tmp/f'theme{uid}.jpg'
            path=f'Data_Base/BOARDFS/GUI_STYLE/GUIS_RESSOURCES/Harmony{uid}/skin.jpg'
            run_cmd('mcopy','-i',str(system),'::/'+path,str(target))
            source=tmp/f'USB-theme{uid}.jpg'
            run_cmd('mcopy','-i',str(run/'usb.raw')+'@@1048576',f'::/PREVIEWS/theme{uid}.jpg',str(source))
            require(target.read_bytes()==source.read_bytes(),'Preview readback mismatch')
            previews.append(dict(path=path,bytes=target.stat().st_size,sha256=hashlib.sha256(target.read_bytes()).hexdigest()))
    report=dict(scope='Stopped sandbox only; physical devices untouched',NAND=str(after),
                all_seven_databases_valid=True,active_theme_flags=flags,theme_names=names,
                selected_HMI_theme=selected,native_Harmony_ini_hex=snap['Harmony.ini'].hex(),
                selected_WARMLIGHT_preserved=selected==[11] and snap['Harmony.ini']==b'HARMONY=201\0',
                databases=dbs,ordinary_session_state_changes=volatile,
                USB_device_enumeration_state_changes=device_state,
                unexpected_non_theme_setting_changes=unexpected,preview_files_verified=previews,
                original_application_byte_exact=snap['containers'][0]['full_native_payload_exact'],
                UI_visual_verification='Must be assessed separately from screenshots')
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ['all_seven_databases_valid','selected_WARMLIGHT_preserved',
                                          'active_theme_flags','theme_names','unexpected_non_theme_setting_changes']},indent=2))
    print('Ordinary session changes:',len(volatile),'Preview files verified:',len(previews))


if __name__=='__main__':main()
