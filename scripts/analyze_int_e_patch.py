#!/usr/bin/env python3
"""Compare native 5.43 gates and prepare guarded RAM-only emulator patches."""
import gzip
import hashlib
import json
from pathlib import Path
from capstone import Cs, CS_ARCH_PPC, CS_MODE_32, CS_MODE_BIG_ENDIAN

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'artifacts/phase10/int-e-patch'
md=Cs(CS_ARCH_PPC,CS_MODE_32|CS_MODE_BIG_ENDIAN)


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    profiles={}
    for variant in ('AUDIO_BT_256','NAV'):
        root=ROOT/'artifacts/phase2'
        text=gzip.decompress((root/'filesystems'/variant/'system/Application/PKG/abs_symbols_base.txt.gz').read_bytes()).decode('latin1')
        symbols={r[2]:int(r[0],16) for line in text.splitlines() if len(r:=line.split())==3}
        image=root/'applications'/variant/'app.bin'
        with image.open('rb') as f:
            def read(address,length):
                f.seek(address-0x1000000);return f.read(length)
            browser=symbols['_ZN22C_HMI_ClientDesktopFsm23GetInternetAvailabilityERbS0_']
            body=read(browser,940)
            (OUT/(variant+'-browser.txt')).write_text('\n'.join(
                f'{i.address:08x} {i.bytes.hex()} {i.mnemonic} {i.op_str}'
                for i in md.disasm(body,browser))+'\n')
            ctors=[symbols['_ZN15C_BCM_BT_AGENDAC1Ev'],symbols['_ZN15C_BCM_BT_AGENDAC2Ev']]
            stores=[]
            for address in ctors:
                pc=address+0xc0
                assert read(pc,4).hex()=='981d00ba'
                assert read(pc-16,4).hex()=='39600000'  # r11=0, before the store
                stores.append({'constructor':hex(address),'store':hex(pc),
                               'old':'981d00ba','new':'997d00ba',
                               'meaning':'stb r0,0xba(r29) -> stb r11,0xba(r29), with verified r11=0'})
            profiles[variant]={'image':str(image.relative_to(ROOT)),
                'sha256':hashlib.file_digest(image.open('rb'),'sha256').hexdigest(),
                'browser':hex(browser),'hardware_branch':hex(browser+0x348),
                'hardware_bytes':read(browser+0x348,4).hex(),
                'web_branch':hex(browser+0x2cc),'web_bytes':read(browser+0x2cc,4).hex(),
                'hardware_boolean_tail':read(browser+0x30c,0x7c).hex(),
                'agenda_stores':stores}
    a,n=profiles['AUDIO_BT_256'],profiles['NAV']
    assert a['hardware_bytes']==n['hardware_bytes']=='409e0010'
    assert a['web_bytes']==n['web_bytes']=='409e008c'
    assert a['hardware_boolean_tail']==n['hardware_boolean_tail']
    hardware={'pc':a['hardware_branch'],'old':'409e0010','new':'60000000',
              'reason':'NOP only the conditional rejection for HW_FLAG_SMEG_INT_E'}
    web={'pc':a['web_branch'],'old':'409e008c','new':'60000000',
         'reason':'Separate prerequisite experiment: NOP Web_active rejection in RAM; DB remains 0'}
    agenda=[{'pc':s['store'],'old':s['old'],'new':s['new'],'reason':s['meaning']} for s in a['agenda_stores']]
    plans={'stock':[],'int_e_only':[hardware],'agenda_only':agenda,
           'int_e_agenda':[hardware]+agenda,'int_e_web_ram':[hardware,web],
           'int_e_web_agenda':[hardware,web]+agenda}
    backend_profiles={}
    for variant,method in (('AUDIO_BT_256',0x4c170c0),('NAV',0x4c1c238)):
        image=ROOT/'artifacts/phase2/applications'/variant/'app_segment2.bin'
        with image.open('rb') as f:
            f.seek(method-0x4c00000);body=f.read(308)
        assert body[0xb4:0xb8].hex()=='8b9e0000'
        assert body[0xfc:0x100].hex()=='7c630034'
        (OUT/(variant+'-backend.txt')).write_text('\n'.join(
            f'{i.address:08x} {i.bytes.hex()} {i.mnemonic} {i.op_str}'
            for i in md.disasm(body,method))+'\n')
        backend_profiles[variant]={'method':hex(method),'Web_active_load':hex(method+0xb4),
            'Web_load_bytes':'8b9e0000','RAM_limit_inversion':hex(method+0xfc),
            'RAM_inversion_bytes':'7c630034'}
    ram={'pc':'0x4c171bc','old':'7c630034','new':'38600020',
         'reason':'RAM-only diagnostic: replace cntlzw of IsRamSizeLimited result with li r3,32; following srwi yields 1. All remaining availability terms retained.'}
    backend_web={'pc':'0x4c17174','old':'8b9e0000','new':'3b800001',
         'reason':'Separate RAM-only prerequisite bypass: use local Web_active=1 instead of loading the unchanged stored flag.'}
    plans.update(all_hardware_gates=[hardware,ram],
                 all_gates_web_ram=[hardware,web,ram,backend_web],
                 backend_only_web_ram=[ram,backend_web],
                 all_gates_web_agenda=[hardware,web,ram,backend_web]+agenda)
    bt_menu=[]
    with (ROOT/'artifacts/phase2/applications/AUDIO_BT_256/app.bin').open('rb') as f:
        for pc in (0x28200dc,0x28204ec,0x28206d0,0x2820894,0x281f7f4):
            f.seek(pc-0x1000000);old=f.read(4).hex()
            assert old==('419e016c' if pc==0x281f7f4 else '419e0054')
            bt_menu.append({'pc':hex(pc),'old':old,'new':'60000000',
                'reason':'RAM-only diagnostic: bypass IsSmegIntegratedEHW conditional in Bluetooth contextual-menu creation/action; retain original cached hardware identity.'})
    with (ROOT/'artifacts/phase2/applications/NAV/app.bin').open('rb') as f:
        for item in bt_menu:
            nav_pc=int(item['pc'],16)+0x140
            f.seek(nav_pc-0x1000000)
            assert f.read(4).hex()==item['old']
    plans['bluetooth_menu_only']=bt_menu
    plans['browser_and_bluetooth_menu']=[hardware,web,ram,backend_web]+bt_menu
    plans['interactive_combined']=[hardware,web,ram,backend_web]+bt_menu+agenda
    segment=ROOT/'artifacts/phase2/applications/AUDIO_BT_256/app_segment2.bin'
    with segment.open('rb') as f:
        # IsRamSizeLimited loads this address then invokes
        # C_CONFIG_SYSTEM::GetValue(const char*) at0x0112bbf0.
        f.seek(0x58a2804-0x4c00000)
        hardware_key=f.read(64).split(b'\0')[0].decode('ascii')
    assert hardware_key=='HW_FLAG_SMEG_INT_E'
    result={'profiles':profiles,'hardware_boolean_logic_byte_identical':True,
            'comparison_conclusion':'NAV has the same INT_E exclusion; prior working NAV/INT_F fixture passes due to hardware flags, not absence of this branch.',
            'original_database_Web_active':0,'database_modifications':False,
            'patch_method':'Fingerprint-guarded writes to loaded application RAM in QEMU only; no NAND firmware or physical update package.',
            'cases':plans,'physical_device_access':False,
            'bluetooth_context_menu':{'hardware_read':'0x27bb564',
                'cached_INT_E_offset':'0x51006',
                'getter':'0x27b2b10 C_HMI_BT_APP_BASE::IsSmegIntegratedEHW()',
                'menu_creation_branches':[hex(a) for a in (0x28200dc,0x28204ec,0x28206d0,0x2820894)],
                'menu_action_branch':'0x281f7f4',
                'NAV_same_conditional_instructions':True,
                'NAV_addresses':[hex(int(p['pc'],16)+0x140) for p in bt_menu]},
            'backend':{'image':str(segment.relative_to(ROOT)),
                'image_sha256':hashlib.file_digest(segment.open('rb'),'sha256').hexdigest(),
                'runtime_base':'0x4c00000, accepted only with live instruction fingerprint match',
                'manager':'0x4c170c0','ram_gate':'0x4c171bc','Web_active_local_read':'0x4c17174',
                'scope':'IsRamSizeLimited calls C_CONFIG_SYSTEM::GetValue with HW_FLAG_SMEG_INT_E; this is a second explicit INT_E exclusion. Physical RAM compatibility is unverified.',
                'IsRamSizeLimited':{'address':'0x4c0af98','configuration_getter':'0x112bbf0',
                    'key_address':'0x58a2804','configuration_key':hardware_key},
                'NAV_comparison':backend_profiles,
                'comparison_conclusion':'Both profiles contain the same Web_active load and RAM-limit inversion. AUDIO IsRamSizeLimited reads HW_FLAG_SMEG_INT_E, so live return1 is a hardware-profile policy even with512MiB guest RAM.'}}
    (OUT/'analysis.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'analysis':str(OUT/'analysis.json'),'browser':a['browser'],
                      'INT_E_branch':a['hardware_branch'],'phonebook_stores':[s['store'] for s in a['agenda_stores']],
                      'same_hardware_logic_in_NAV':True,'cases':list(plans)}))


if __name__=='__main__':main()
