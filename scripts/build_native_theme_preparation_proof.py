#!/usr/bin/env python3
"""Bind completed native-install, cold-boot and preservation evidence to one USB."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'artifacts/phase20'
def read(name):return json.loads((BASE/name).read_text())
def sha(p):
    with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def need(test,message):
    if not test:raise ValueError(message)
def main():
    output=BASE/'physical-theme-preparation-proof.json'
    need(not output.exists(),'Preserve existing proof')
    meta=read('complete-stock-probe-v7/usb.json')
    oldmeta=read('complete-stock-probe-v6/usb.json')
    need(meta['banks']==oldmeta['banks'],'Theme assets changed since navigation coverage')
    need(sha(BASE/'complete-stock-probe-v7/usb.raw')==meta['image_sha256'],'USB changed')
    settings=read('final-v7-cold-settings-audit.json')
    resources=read('final-v7-cold-resource-defined-audit.json')
    system=read('final-v7-SYSTEM-preservation-audit.json')
    visual=read('final-v7-visual-review.json')
    names={'GRAPHIC','ELLIPTIC','CUBIC','REFLEX','ESSENTIEL','REDLINE','SQUARE','WARMLIGHT'}
    need(set(filter(None,settings['theme_names'].values()))==names,'Cold catalogue incomplete')
    need(settings['all_seven_databases_valid']and settings['selected_WARMLIGHT_preserved']and not settings['unexpected_non_theme_setting_changes'],'Settings preservation failed')
    # The broad audit permits theme housekeeping; restrict actual changed
    # persistent rows to the six flags, six names, twelve mappings and counter.
    ids=(1,2,3,4,7,8)
    allowed={('up_config.sqlite','display',f'Harm_{i}',0)for i in ids}
    allowed|={('up_config.sqlite','upgrade','HarmoniesChecked',0)}
    allowed|={('up_common.sqlite','supervisor',f'harmony{i}',0)for i in ids}
    allowed|={('up_common.sqlite','supervisor',f'harm{i}_{suffix}',0)for i in ids for suffix in ('number','offset_area')}
    session={tuple(r['key'])for r in settings['ordinary_session_state_changes']}
    usb={tuple(r['key'])for r in settings['USB_device_enumeration_state_changes']}
    for database in settings['databases']:
        for change in database['differences_from_latest_live_export']:
            need(change.get('table')=='UP_Keys'and not change.get('schema_changed'),'Unexpected schema change')
            for row in change['removed']+change['added']:
                key=(row['Section'],row['Name'],row['Idx'])
                need((database['name'],*key)in allowed or (database['name']=='up_common.sqlite'and key in session|usb),'Unrequested settings changed: '+repr(key))
    need(resources['native_install_success']and resources['original_application_byte_exact'],'Native installation/binary preservation failed')
    need(len(resources['resources'])==2 and all(r['all_defined_resource_bytes_exact']and r['preheader_byte_exact']and r['directory_byte_exact']and all(e['source_payload_byte_exact']and e['stored_CRC32_valid']for e in r['entries'])for r in resources['resources']),'Defined resource readback failed')
    need(resources['non_theme_setting_differences']==[],'Unclassified resource-audit settings change')
    need(system['changed_original_files']==[]and system['original_SYSTEM_files_byte_exact']==238 and len(system['added_SYSTEM_files'])==6,'SYSTEM preservation failed')
    need(system['persisted_portal']=='/SYSTEM/internet_default/portal/index.html','Custom app mixed into theme image')
    need(set(visual['selector_names_visually_observed'])==names and visual['selected_theme_preserved']is True,'Native selector not visually verified')
    runtime=ROOT/'artifacts/phase15/runtime-P20FINALCAT8'
    result=json.loads((runtime/'result.json').read_text())
    need(result['exit_code']==0 and result['source_unchanged']and not result['serial_exception_lines'],'Cold runtime failure')
    need(not result['guest_RAM_patches']and not result['USB_attached']and result['ram_mib']==256 and not result['host_memory_routine_acceleration'],'Runtime fidelity mismatch')
    run=ROOT/'artifacts/phase8/usb-maintenance/runs/T21COMPLETE08'
    native=json.loads((run/'result.json').read_text())
    need(native['returncode']==0 and native['wait_marker_seen']and native['native_memory_requested'],'Native USB test incomplete')
    need(sha(run/'nand.raw')==result['source_sha256'],'Cold source differs from actual installation')
    second=ROOT/'artifacts/phase15/runtime-P20FINALCAT9/result.json'
    repeat=json.loads(second.read_text())
    need(repeat['exit_code']==0 and repeat['source_unchanged']and not repeat['serial_exception_lines']and not repeat['USB_attached']and not repeat['guest_RAM_patches'],'Second USB-free boot failed')
    need(repeat['source_sha256']==result['stopped_nand_sha256'],'Second cold source mismatch')
    navigation=read('registered-theme-navigation/verification.json')
    need(set(navigation['verified_theme_names'])==names,'Navigation coverage incomplete')
    files=[BASE/n for n in ['complete-stock-probe-v7/usb.json','complete-stock-probe-v7/independent-readback.json','final-v7-cold-settings-audit.json','final-v7-cold-resource-defined-audit.json','final-v7-SYSTEM-preservation-audit.json','final-v7-visual-review.json','registered-theme-navigation/verification.json','registered-theme-navigation/results.json','physical-before/copy-manifest.json']]
    files += [run/'result.json',runtime/'result.json',runtime/'serial.log',second]
    for record in visual['screenshots']:
        p=ROOT/record['path'];need(p.is_relative_to(BASE)and sha(p)==record['sha256'],'Reviewed screenshot changed');files.append(p)
    proof=dict(single_USB_stock_to_eight_theme_install_and_cold_boot_verified=True,candidate_USB_sha256=meta['image_sha256'],original_application_binary_byte_exact=True,selected_WARMLIGHT_preserved=True,all_seven_databases_integrity_INF_valid=True,unexpected_non_theme_setting_changes=[],verified_theme_names=sorted(names),critical_guest_failures=[],known_cosmetic_limitations=['ELLIPTIC: clock overlaps the source header','CUBIC: clock overlaps the source-panel border'],known_emulator_warning='Virtual anti-theft ECU reports WAITING_VIN_TIMEOUT; this is not a physical-car compatibility certification',physical_car_compatibility_certified=False,evidence=[dict(path=str(p),sha256=sha(p))for p in files])
    proof['native_writer_undefined_alignment_padding_bytes_changed']={str(r['bank']):r['undefined_padding_bytes_changed']for r in resources['resources']}
    proof['all_defined_resource_bytes_exact']=True
    output.write_text(json.dumps(proof,indent=2)+'\n');print(output)
if __name__=='__main__':main()
