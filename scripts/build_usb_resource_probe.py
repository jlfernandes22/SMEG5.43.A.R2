#!/usr/bin/env python3
"""Build QEMU-only native resource writer probe; never accesses block devices."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import shutil
import zlib

from inspect_internet_harmony import bank, PAGE, SLOT_SIZE, PACKAGE
from prepare_all_theme_assets import seal_inf, parse_candidate
from smeg_db_inf import crc16
from audit_persistent_candidate import native_payload
from theme_resource_format import native_bank

ROOT = Path(__file__).resolve().parents[1]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fnv(data):
    value = 2166136261
    for byte in data:
        value = ((value ^ byte) * 16777619) & 0xffffffff
    return value


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--all-six', action='store_true')
    p.add_argument('--erase-header', action='store_true', help='Use native per-bank header erasure before writing')
    p.add_argument('--resume-bank2', action='store_true', help='Require the verified first expanded bank and install only bank2')
    p.add_argument('--replace-expanded', action='store_true', help='Require both previously installed expanded banks')
    p.add_argument('--ported-menus', action='store_true', help='Use prior sandbox compatibility resources for the six added themes only')
    p.add_argument('--erase-all-banks', action='store_true', help='Native full erasure of both resource slots after validating both replacement files')
    p.add_argument('--assets', type=Path, help='Verified compatibility asset directory, used with --ported-menus')
    p.add_argument('--complete-installer', action='store_true', help='Export originals, install both banks and previews, then request six theme flags')
    p.add_argument('--refresh-catalogue',action='store_true',help='Invalidate only the generated theme-check marker after installation')
    p.add_argument('--register-catalogue',action='store_true',help='Register six verified installed theme names and mappings through native APIs')
    p.add_argument('--native-progress',action='store_true',help='Guarded stock progress/completion popups; no UI asset or instruction patches')
    a = p.parse_args()
    if a.native_progress and not a.complete_installer:p.error('--native-progress requires --complete-installer')
    if a.register_catalogue and not a.refresh_catalogue:p.error('--register-catalogue requires --refresh-catalogue')
    if a.refresh_catalogue and not a.complete_installer:p.error('--refresh-catalogue requires --complete-installer')
    if a.complete_installer and not (a.all_six and a.ported_menus and a.erase_all_banks and not a.replace_expanded):
        p.error('Complete installer requires stock preconditions, all six themes, ported menus and full bank erasure')
    if (a.replace_expanded or a.ported_menus) and not a.erase_all_banks:
        p.error('Replacing occupied resource banks requires --erase-all-banks; header-only erasure is insufficient')
    out = a.output.resolve()
    assert out.is_relative_to(ROOT / 'artifacts/phase20') and not out.exists()
    out.mkdir(parents=True)
    parsed = {g: bank(g) for g in range(1, 6)}
    plans = {4: [(4, 0, 10), (1, 0, 1)]}
    if a.all_six:
        plans = {4: [(4, 0, 10), (1, 0, 1), (2, 0, 8), (2, 2, 7)],
                 5: [(5, 0, 11), (1, 1, 2), (1, 2, 3), (2, 1, 4)]}
    if a.resume_bank2:
        assert a.all_six and a.erase_header
        plans.pop(4)
    assert not (a.resume_bank2 and a.replace_expanded)
    assert not (a.erase_header and a.erase_all_banks)
    if a.erase_all_banks:assert a.all_six and not a.resume_bank2
    if a.replace_expanded:assert a.all_six and (a.erase_header or a.erase_all_banks)
    ported={}
    ported_provenance=[]
    if a.ported_menus:
        asset_dir=(a.assets or ROOT/'artifacts/phase15/theme-assets/all-eight-menu-colour-style-v7').resolve()
        assert asset_dir.is_relative_to(ROOT/'artifacts/phase15/theme-assets')
        manifest=json.loads((asset_dir/'manifest.json').read_text())
        for group in (4,5):
            rel=f'HARMONY/BigHarmony_{group}/BIG_HARMONY.bin'
            path=asset_dir/'overlay'/rel
            raw=path.read_bytes()
            expected=next(r for r in manifest['files'] if r['path']==rel)
            assert sha(raw)==expected['SHA256']
            count=struct.unpack_from('>I',raw,2080)[0]
            parse_candidate(raw,36+count*216)
            for idx in range(count):
                record=raw[2084+idx*216:2084+(idx+1)*216]
                uid,page,size,crc=struct.unpack_from('>IIII',record,200)
                if uid in (1,2,3,4,7,8):ported[uid]=(record,raw[page*2048:page*2048+size])
            ported_provenance.append(dict(path=str(path),sha256=sha(raw)))
        assert len(ported)==6
    files, contracts, banks = {}, [], []
    for group, plan in plans.items():
        template, _, _ = parsed[group]
        data = bytearray(template[:PAGE] + b'\0' * PAGE)
        data[PAGE:PAGE+32] = template[PAGE:PAGE+32]
        struct.pack_into('>I', data, PAGE+32, len(plan))
        cursor = 2
        sources = []
        for index, (donor, source_index, uid) in enumerate(plan):
            src, _, entries = parsed[donor]
            record = bytearray(src[PAGE+36+216*source_index:PAGE+36+216*(source_index+1)])
            payload = entries[source_index]['_payload']
            if uid in ported:
                donor_record,payload=ported[uid]
                assert donor_record[:196].split(b'\0')[0]==record[:196].split(b'\0')[0]
                record=bytearray(donor_record)
            struct.pack_into('>IIIII', record, 196, index, uid, cursor, len(payload), zlib.crc32(payload))
            data[PAGE+36+216*index:PAGE+36+216*(index+1)] = record
            data.extend(payload + b'\xff' * (-len(payload) % PAGE))
            cursor += (len(payload) + PAGE - 1) // PAGE
            sources.append(dict(name=entries[source_index]['theme'], donor_group=donor,
                                donor_index=source_index, uid=uid, compressed_sha256=sha(payload)))
        data = bytes(data)
        header_size = 36 + len(plan) * 216
        assert len(data) <= SLOT_SIZE
        parse_candidate(data, header_size)
        hcrc = zlib.crc32(data[PAGE:PAGE+header_size])
        inf = seal_inf((PACKAGE / f'BigHarmony_{group}/BIG_HARMONY.bin.inf').read_bytes(), data,
                       {f'BigHarmony_{group}': ';'.join(str(x[2]) for x in plan),
                        'HEADER_SIZE': header_size,
                        'HEADER_CRC32': struct.unpack('>i', struct.pack('>I', hcrc))[0]})
        name = f'THEME_TEST/bank{group-3}.bin'
        files[name], files[name+'.inf'] = data, inf
        original = out / f'bank{group-3}.bin'
        original.write_bytes(data)
        Path(str(original)+'.inf').write_bytes(inf)
        native = native_bank(data, inf)
        contracts.append((group-3, '/bd0/'+name, len(data), zlib.crc32(data),
                          fnv(native[:168]), fnv(native[PAGE:PAGE+36]), len(plan),
                          [fnv(native[PAGE+36+i*216:PAGE+36+(i+1)*216]) for i in range(len(plan))]))
        banks.append(dict(bank=group-3, bytes=len(data), sha256=sha(data), entries=sources,
                          original_first_payload_preserved=True))
    kernel_path = ROOT / 'artifacts/phase2/package/SMEG_PLUS_UPG/BSP/SMEG_PLUS_256/vxWorks.bin'
    kernel = kernel_path.read_bytes()
    names = ['ReadBigHarmonyPreHeader', 'ReadBigHarmonyBigHeader', 'ReadBigHarmonyHeader', 'WriteBigHarmony']
    if a.erase_header:
        names.append('EraseNandHarmony')
    if a.erase_all_banks:
        names.append('EraseAllHarmonies')
    read_api_index=len(names)
    if a.complete_installer:
        names.append('ReadBigHarmony')
    text = gzip.decompress((ROOT / 'artifacts/phase2/filesystems/AUDIO_BT_256/system/Application/PKG/symbols_bsp.txt.gz').read_bytes()).decode('latin1')
    syms = {parts[2]: int(parts[0], 16) for line in text.splitlines() if len(parts := line.split()) == 3}
    checks = [dict(name=n, address=syms[n], bytes=64, hash=fnv(kernel[syms[n]-0x200000:syms[n]-0x200000+64])) for n in names]
    pre_hashes=[fnv(native_payload(PACKAGE / f'BigHarmony_{g}/BIG_HARMONY.bin')[:168]) for g in (4,5)]
    prerequisite=None
    if a.resume_bank2 or a.replace_expanded:
        prior=[]
        for group,expected in [(1,'8090dff40805648fd869908b729920bf27e2d510bd8cfc5dc1b742062d67ce79'),
                               (2,'7d01b16c14143ff6a0ac494c1ca83e391278f2b8fd223faa9f0baa022bcae37d')]:
            if group==2 and not a.replace_expanded:continue
            existing=ROOT/f'artifacts/phase20/all-six-resource-probe-v2/bank{group}.bin'
            assert sha(existing.read_bytes())==expected
            pre_hashes[group-1]=fnv(native_bank(existing.read_bytes(),Path(str(existing)+'.inf').read_bytes())[:168])
            prior.append(dict(bank=group,file=str(existing),sha256=expected))
        prerequisite=prior[0] if a.resume_bank2 else prior
    headers = ['struct ResourceAPI {unsigned address,bytes,hash;};',
               'static const struct ResourceAPI resource_api[] = {',
               *['{0x%xu,%du,0x%xu},' % (r['address'], r['bytes'], r['hash']) for r in checks], '};',
               'static const unsigned original_pre_hash[] = {' + ','.join('0x%xu' % h for h in pre_hashes) + '};',
               'struct ResourceFile {unsigned bank; const char *path; unsigned bytes,crc32,pre_hash,big_hash,count,entry_hash[4];};',
               'static const struct ResourceFile resource_files[] = {']
    for b, path, size, crc, pre, big, count, entries in contracts:
        headers.append('{%du,"%s",%du,0x%xu,0x%xu,0x%xu,%du,{%s}},' %
                       (b, path, size, crc, pre, big, count, ','.join('0x%xu' % h for h in entries)))
    headers += ['};', '#define RESOURCE_COUNT %du' % len(contracts)]
    sidecars=[]
    headers += ['struct ResourceInfFile {const char *path;unsigned bytes,crc32;};',
                'static const struct ResourceInfFile resource_inf_files[] = {']
    for b,*_ in contracts:
        name=f'THEME_TEST/bank{b}.bin.inf';data=files[name]
        headers.append('{"/bd0/%s",%du,0x%xu},'%(name,len(data),zlib.crc32(data)))
        sidecars.append(dict(path=name,bytes=len(data),crc32='%08x'%zlib.crc32(data),sha256=sha(data)))
    headers += ['};','#define RESOURCE_INF_COUNT %du'%len(sidecars)]
    table = []
    for byte in range(256):
        value = byte
        for _ in range(8):
            value = (value >> 1) ^ (0xedb88320 if value & 1 else 0)
        table.append(value)
    headers += ['static const unsigned resource_crc_table[256] = {' +
                ','.join('0x%xu' % value for value in table) + '};']
    if a.erase_header:
        headers += ['#define RESOURCE_ERASE_HEADER 1']
    if a.erase_all_banks:
        headers += ['#define RESOURCE_ERASE_ALL 1']
    if a.complete_installer:
        maximum=max(struct.unpack_from('>I',files[f'THEME_TEST/bank{b}.bin'],2084+i*216+208)[0]
                    for b in (1,2) for i in range(4))
        headers += ['#define RESOURCE_COMPLETE_READBACK 1',
                    f'#define RESOURCE_READ_API {read_api_index}',
                    f'#define RESOURCE_MAX_PAYLOAD_BYTES {((maximum+2047)//2048+1)*2048}u']
        preview_dir=ROOT/'artifacts/phase20/theme-activation-probe-v3'
        for name in ('theme_preview_contract.h','theme_preview_fs_contract.h','usb_warmlight_api_fingerprints.h'):
            shutil.copyfile(preview_dir/name,out/name)
        if a.refresh_catalogue:
            shutil.copyfile(ROOT/'artifacts/phase20/catalogue-marker-probe/theme_catalogue_contract.h',out/'theme_catalogue_contract.h')
        if a.register_catalogue:
            from build_usb_common_catalogue import contract
            catalogue_rows=contract(out,out)
        from prepare_all_theme_assets import previews
        for group,uid in [(1,1),(1,2),(1,3),(2,4),(2,7),(2,8)]:
            files[f'PREVIEWS/theme{uid}.jpg']=previews(group,'AUDIO')[uid][1]
    (out / 'theme_resource_contract.h').write_text('\n'.join(headers)+'\n')
    progress_contract=None
    if a.native_progress:
        from theme_progress_contract import write_contract
        progress_contract=write_contract(ROOT,out)
    source = ROOT / ('emulation/usb_complete_themes_sandbox.c' if a.complete_installer else 'emulation/usb_install_theme_resources_sandbox.c')
    (out/'source.c').write_bytes(source.read_bytes())
    module = out / 'theme_resources.out'
    command = ['clang', '--target=powerpc-unknown-linux-gnu', '-mbig-endian', '-m32', '-mlongcall',
               '-ffreestanding', '-fno-pic', '-fno-stack-protector', '-fno-unwind-tables',
               '-fno-asynchronous-unwind-tables', '-msoft-float', '-I', str(out), '-I', str(ROOT/'emulation'),
               '-O2', '-Wall', '-Wextra', '-Werror', '-c', str(source), '-o', str(module)]
    if a.refresh_catalogue:command.insert(1,'-DSMEG_COMPLETE_REFRESH_CATALOGUE=1')
    if a.register_catalogue:command.insert(1,'-DSMEG_COMPLETE_REGISTER_CATALOGUE=1')
    if a.native_progress:command.insert(1,'-DSMEG_NATIVE_THEME_PROGRESS=1')
    subprocess.run(command, check=True)
    payload = module.read_bytes()
    body = (f'{crc16(payload):04x}\r\nVER:SMEG5.43.A.R2\r\nTYPE:RELOCABLE\r\nID:0\r\n'
            f'COMPRESSED:NO\r\nSIZE:{len(payload)}\r\nENTRY:YES\r\n').encode()
    doctor = b'0000\r\nACTION:TemporaryBootRom\r\nLOAD_AND_EXECUTE:/bd0/FLYING/theme_resources.out\r\n'
    files.update({'FLYING/theme_resources.out': payload,
                  'FLYING/theme_resources.out.inf': f'{crc16(body):04x}'.encode()+body,
                  'FLYING/doctor_smeg_plus_i.inf': f'{crc16(doctor):04x}'.encode()+doctor})
    image = out / 'usb.raw'
    size, offset = 128*1024**2, 1048576
    env = dict(os.environ, MTOOLS_SKIP_CHECK='1')
    def run(*cmd):
        return subprocess.run(cmd, check=True, capture_output=True, env=env)
    with tempfile.TemporaryDirectory(prefix='smeg-resource-probe-') as temp:
        tmp = Path(temp)
        fat = tmp / 'fat'
        with fat.open('xb') as f:
            f.truncate(size)
        run('mkfs.vfat', '-F', '32', '-n', 'QEMU_RES', str(fat))
        mbr = bytearray(512)
        mbr[446:462] = struct.pack('<B3sB3sII', 0, b'\xfe\xff\xff', 12, b'\xfe\xff\xff', offset//512, size//512)
        mbr[510:] = b'\x55\xaa'
        with image.open('xb') as f:
            f.write(mbr); f.seek(offset)
            with fat.open('rb') as src:
                while chunk := src.read(1024**2):
                    f.write(chunk)
        spec = str(image)+'@@'+str(offset)
        for directory in ('FLYING', 'THEME_TEST', *(['PREVIEWS'] if a.complete_installer else [])):
            run('mmd', '-i', spec, '::/'+directory)
        for i, (name, data) in enumerate(files.items()):
            src, check = tmp/str(i), tmp/('readback'+str(i))
            src.write_bytes(data); run('mcopy', '-i', spec, str(src), '::/'+name)
            run('mcopy', '-i', spec, '::/'+name, str(check))
            assert check.read_bytes() == data
    metadata = dict(emulator_only=True, physical_car_approved=False, physical_device_access=False,
                    image=str(image), image_sha256=sha(image.read_bytes()),
                    configuration_setters=a.complete_installer, replacement_databases=False,
                    requested_configuration_flags=['display.Harm_'+str(uid)+'.0=1'for uid in (1,2,3,4,7,8)] if a.complete_installer else [],
                    complete_stock_to_eight_theme_installer=a.complete_installer,
                    native_theme_catalogue_registration=a.register_catalogue,
                    requested_theme_catalogue_rows=catalogue_rows if a.register_catalogue else [],
                    generated_theme_cache_marker_invalidated=a.refresh_catalogue,
                    native_progress_contract=progress_contract,
                    removed_cache_marker='/SYSTEM_TMP_DATA/HarmoniesChecked.tst'if a.refresh_catalogue else None,
                    full_native_payload_backup_and_readback=a.complete_installer,
                    source_sidecar_preflight=True,source_sidecar_files=sidecars,
                    application_or_BSP_writes=False, auto_reboot=False,
                    native_per_bank_header_erasure=a.erase_header,
                    native_full_resource_bank_erasure=a.erase_all_banks,
                    preinstalled_bank_prerequisite=prerequisite,
                    six_added_themes_use_prior_MENU_compatibility_resources=a.ported_menus,
                    menu_resource_provenance=ported_provenance,
                    banks=banks, api_checks=checks, native_writer_signature='int WriteBigHarmony(int bank, const char *file)',
                    source_sha256=sha(source.read_bytes()), kernel_sha256=sha(kernel), compile_command=command,
                    files=[dict(path=n, bytes=len(d), sha256=sha(d)) for n,d in files.items()])
    (out/'usb.json').write_text(json.dumps(metadata, indent=2)+'\n')
    print(json.dumps({'image':str(image), 'banks':banks, 'emulator_only':True}, indent=2))


if __name__ == '__main__':
    main()
