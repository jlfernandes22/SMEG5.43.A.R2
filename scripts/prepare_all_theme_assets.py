#!/usr/bin/env python3
"""Inventory original Harmony assets; optionally pack an emulator-test Audio overlay.

No NAND, USB, candidate-v5, database or firmware instructions are written. Eight
names use eight distinct original compiled resources, not relabelled SQUARE.
This is asset/container validation, not native selection or physical-car proof.
"""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import tarfile
import zlib
from inspect_internet_harmony import ROOT, PACKAGE, PAGE, SLOT_SIZE, bank
from smeg_db_inf import crc16

OUTROOT=ROOT/'artifacts/phase15/theme-assets'
# source bank/index, target universal ID; retain current Audio101/201 entries.
LAYOUT={4:[(3,0,10),(1,0,1),(2,0,8),(2,2,7)],
        5:[(3,1,11),(1,1,2),(1,2,3),(2,1,4)]}


def sha(data):return hashlib.sha256(data).hexdigest()


def seal_inf(original,payload,updates=None):
    assert int(original[:4],16)==crc16(original[4:])
    body=original[8:]
    for name,value in (updates or {}).items():
        body,n=re.subn(rb'(?m)^'+re.escape(name.encode())+rb':[^\r\n]*',
                       (name+':'+str(value)).encode(),body)
        assert n==1,(name,n)
    tail=f'{crc16(payload):04x}'.encode()+body
    result=f'{crc16(tail):04x}'.encode()+tail
    assert int(result[:4],16)==crc16(result[4:])
    assert int(result[4:8],16)==crc16(payload)
    return result


def previews(group,kind):
    p=PACKAGE/f'BigHarmony_{group}/BIG_SKIN_{kind}.bin'
    result={}
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(p.read_bytes())),mode='r:') as tf:
        for member in tf:
            assert member.isfile() and re.fullmatch(r'Harmony\d+/skin\.jpg',member.name)
            data=tf.extractfile(member).read()
            assert data[:2]==b'\xff\xd8'
            result[int(member.name.split('/')[0][7:])] = (member,data)
    return result


def parse_candidate(data,header_size):
    assert data[:10]==b'BIGHARMONY'
    count=struct.unpack_from('>I',data,PAGE+32)[0]
    assert header_size==36+216*count and header_size<=PAGE
    entries=[];ranges=[]
    for i in range(count):
        r=data[PAGE+36+216*i:PAGE+36+216*(i+1)]
        name=r[:196].split(b'\0')[0].decode('ascii')
        index,uid,page,size,crc=struct.unpack_from('>IIIII',r,196)
        assert index==i and uid in range(1,13)
        start=page*PAGE;assert start>=2*PAGE
        payload=data[start:start+size];assert len(payload)==size and zlib.crc32(payload)==crc
        expanded=zlib.decompress(payload[4:]);assert len(expanded)==struct.unpack_from('>I',payload)[0]
        ranges.append((start,start+size))
        entries.append({'name':name,'index':index,'universal_id':uid,'page':page,'payload_bytes':size,
                        'compressed_SHA256':sha(payload),'expanded_SHA256':sha(expanded),
                        'expanded_bytes':len(expanded)})
    assert len({x['universal_id'] for x in entries})==count
    assert all(a[1]<=b[0] for a,b in zip(sorted(ranges),sorted(ranges)[1:]))
    return entries


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output',type=Path,default=OUTROOT/'inventory01')
    ap.add_argument('--build',action='store_true')
    a=ap.parse_args();out=a.output.resolve()
    if not out.is_relative_to(OUTROOT) or out.exists():ap.error('New output directory inside artifacts/phase15/theme-assets required')
    out.mkdir(parents=True)
    parsed={g:bank(g) for g in range(1,6)}
    sources={p:sha(p.read_bytes()) for p in PACKAGE.rglob('*') if p.is_file()}
    rows=[]
    for g,(data,inf,items) in parsed.items():
        for i,item in enumerate(items):
            record=data[PAGE+36+216*i:PAGE+36+216*(i+1)]
            idx,uid,page,size,crc=struct.unpack_from('>5I',record,196)
            raw=zlib.decompress(item['_payload'][4:])
            windows=[struct.unpack_from('>4I',raw,0x6c+j*16) for j in range(struct.unpack_from('>I',raw,4)[0])]
            row={k:v for k,v in item.items() if not k.startswith('_') and k!='internet_windows'}
            row.update(source_entry=i,record_index=idx,universal_id=uid,payload_page=page,
                       compressed_bytes=size,compressed_SHA256=sha(item['_payload']),expanded_SHA256=sha(raw),
                       window_applications=sorted({w[0] for w in windows}),Internet_window_count=len(item['internet_windows']),
                       bank_bytes=len(data),bank_header_bytes=int(inf['HEADER_SIZE']),
                       auxiliary_previews={})
            for kind in ['AUDIO','NAV']:
                member,preview=previews(g,kind)[uid]
                row['auxiliary_previews'][kind]={'member':member.name,'bytes':len(preview),'SHA256':sha(preview)}
                target=out/'original-previews'/kind/f'{uid:02d}-{item["theme"]}.jpg';target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(preview)
            rows.append(row)
    inventory={'scope':'Original source asset inventory; no installation/activation claim','source_package':str(PACKAGE.relative_to(ROOT)),
               'unique_names':sorted({r['theme'] for r in rows}),'entry_count':len(rows),'entries':rows,
               'Audio_bank_addresses':['0x2dc0000','0x4f60000'],'Audio_slot_bytes_each':SLOT_SIZE,
               'Audio_total_capacity':2*SLOT_SIZE,'native_A9_mapping':{'LIST_NAV':[2,0,0,3,0,0],'LIST_AUDIO_BT':[4,5]},
               'all_NAV_variant_payloads_padded_bytes':sum((len(r['_payload'])+PAGE-1)//PAGE*PAGE for g in [1,2,3]for r in parsed[g][2]),
               'all_original_entry_payloads_padded_bytes':sum((len(r['_payload'])+PAGE-1)//PAGE*PAGE for g in range(1,6)for r in parsed[g][2]),
               'all_twelve_original_entries_fit_two_Audio_slots':sum((len(r['_payload'])+PAGE-1)//PAGE*PAGE for g in range(1,6)for r in parsed[g][2])+8192<=2*SLOT_SIZE,
               'representative_selection':{'GRAPHIC':'universal1; original alternative5 retained in source inventory but not packed',
                   'ESSENTIEL':'universal7; original DSvariant12 retained in source inventory but not packed',
                   'SQUARE':'Original NAVuniversal6 payload, external header IDremapped10; same proven v5 payload',
                   'WARMLIGHT':'Original NAVuniversal9 payload, external header IDremapped11; same proven v5 payload'},
               'dependencies':['Whole compiled resource preserved: windows, image directory, shared images, fonts/textures and offsets remain intact.',
                   'Original matching BIG_SKIN_AUDIO/NAV JPEG previews are required for newly advertised HarmonyIDs.',
                   'Native menu eligibility also requires matching Harm_i/name/offset metadata; this script changes no database.',
                   'Selection, resource compatibility, brand restrictions and RAM peak require native coldboot/switch/reboot tests.']}
    (out/'inventory.json').write_text(json.dumps(inventory,indent=2)+'\n')
    # Exact generic BSP256 source constraints: no assumed fixed single-entry bank.
    kernel=ROOT/'artifacts/phase2/package/SMEG_PLUS_UPG/BSP/SMEG_PLUS_256/vxWorks.bin';kb=kernel.read_bytes()
    from capstone import Cs,CS_ARCH_PPC,CS_MODE_32,CS_MODE_BIG_ENDIAN
    cs=Cs(CS_ARCH_PPC,CS_MODE_32|CS_MODE_BIG_ENDIAN)
    evidence=[]
    for start,size in [(0x25f1f4,0x1f0),(0x25f468,0xec),(0x25f554,0x160)]:
        evidence += [{'address':hex(x.address),'bytes':x.bytes.hex(),'instruction':x.mnemonic+' '+x.op_str}
                     for x in cs.disasm(kb[start-0x200000:start-0x200000+size],start)]
    assert any(x['address']=='0x25f2b4' and '0x800' in x['instruction'] for x in evidence)
    assert any(x['address']=='0x25f604' and '0xd8' in x['instruction'] for x in evidence)
    (out/'native-bank-reader.json').write_text(json.dumps({'kernel':str(kernel.relative_to(ROOT)),'SHA256':sha(kb),
        'constraints':{'header_max_bytes':2048,'header_fixed_bytes':36,'entry_bytes':216,'requested_entries':'1-based, bounded by header count','source_existing_four_entry_bank':1},
        'instructions':evidence},indent=2)+'\n')
    manifest={'asset_candidate_only':True,'physical_car_approved':False,'native_installation_tested':False,
              'native_theme_activation_tested':False,'database_changes':False,'candidate_v5_modified':False,'banks':[]}
    if a.build:
        all_uids=[]
        for target_group,plan in LAYOUT.items():
            template,_,_=parsed[target_group]
            prefix=bytearray(template[:2*PAGE]);prefix[PAGE:]=b'\0'*PAGE
            prefix[PAGE:PAGE+32]=template[PAGE:PAGE+32]
            struct.pack_into('>I',prefix,PAGE+32,len(plan))
            payloads=bytearray();entries=[];cursor=2
            for index,(source_group,source_index,target_uid) in enumerate(plan):
                donor,_,items=parsed[source_group];item=items[source_index]
                record=bytearray(donor[PAGE+36+216*source_index:PAGE+36+216*(source_index+1)])
                source_uid=struct.unpack_from('>I',record,200)[0]
                payload=item['_payload'];padded=payload+b'\xff'*(-len(payload)%PAGE)
                struct.pack_into('>5I',record,196,index,target_uid,cursor,len(payload),zlib.crc32(payload))
                prefix[PAGE+36+216*index:PAGE+36+216*(index+1)]=record
                payloads.extend(padded);cursor+=len(padded)//PAGE;all_uids.append(target_uid)
                entries.append({'theme':item['theme'],'source_group':source_group,'source_entry':source_index,
                    'source_universal_id':source_uid,'target_universal_id':target_uid,'hmi_id':target_uid,'physical_code':(target_group-3)*100+index+1,'target_entry_1based':index+1,
                    'offset_area':(target_group-3)*100+index+1,'compressed_payload_unchanged':True,
                    'compressed_SHA256':sha(payload),'expanded_SHA256':sha(zlib.decompress(payload[4:])),
                    'preview_source_group':target_group if target_uid in [10,11] else source_group})
            packaged=bytes(prefix)+bytes(payloads);header_size=36+216*len(plan)
            assert len(packaged)<=SLOT_SIZE and header_size==900
            parsed_candidate=parse_candidate(packaged,header_size)
            assert [r['compressed_SHA256']for r in parsed_candidate]==[r['compressed_SHA256']for r in entries]
            target=out/'overlay/HARMONY'/f'BigHarmony_{target_group}';target.mkdir(parents=True)
            (target/'BIG_HARMONY.bin').write_bytes(packaged)
            hcrc=zlib.crc32(packaged[PAGE:PAGE+header_size]);signed=struct.unpack('>i',struct.pack('>I',hcrc))[0]
            inf=seal_inf((PACKAGE/f'BigHarmony_{target_group}/BIG_HARMONY.bin.inf').read_bytes(),packaged,
                {f'BigHarmony_{target_group}':';'.join(str(r['target_universal_id'])for r in entries),'HEADER_SIZE':header_size,'HEADER_CRC32':signed})
            (target/'BIG_HARMONY.bin.inf').write_bytes(inf)
            aux=[]
            for kind in ['AUDIO','NAV']:
                buffer=io.BytesIO()
                with tarfile.open(fileobj=buffer,mode='w',format=tarfile.USTAR_FORMAT) as tf:
                    for entry in entries:
                        member,data=previews(entry['preview_source_group'],kind)[entry['target_universal_id']]
                        tf.addfile(member,io.BytesIO(data))
                        aux.append({'kind':kind,'member':member.name,'bytes':len(data),'SHA256':sha(data)})
                payload=gzip.compress(buffer.getvalue(),mtime=0)
                old=(PACKAGE/f'BigHarmony_{target_group}/BIG_SKIN_{kind}.bin.inf').read_bytes()
                (target/f'BIG_SKIN_{kind}.bin').write_bytes(payload)
                (target/f'BIG_SKIN_{kind}.bin.inf').write_bytes(seal_inf(old,payload))
                with tarfile.open(fileobj=io.BytesIO(gzip.decompress(payload)),mode='r:') as tf:
                    assert [x.name for x in tf.getmembers()]==[f'Harmony{x["target_universal_id"]}/skin.jpg'for x in entries]
                    for m,e in zip(tf.getmembers(),entries):
                        assert tf.extractfile(m).read()==previews(e['preview_source_group'],kind)[e['target_universal_id']][1]
            manifest['banks'].append({'target_group':target_group,'bytes':len(packaged),'slot_capacity':SLOT_SIZE,'spare_bytes':SLOT_SIZE-len(packaged),
                'SHA256':sha(packaged),'header_count':len(plan),'header_size':header_size,'header_CRC32':f'{hcrc:08x}',
                'INF_payload_outer_CRC16_verified':True,'entries':entries,'auxiliary_previews':aux,
                'preserved_current_first_selection':101 if target_group==4 else 201})
        assert len(all_uids)==len(set(all_uids))==8
        assert len({e["compressed_SHA256"]for b in manifest["banks"]for e in b["entries"]})==8
        assert len({e["expanded_SHA256"]for b in manifest["banks"]for e in b["entries"]})==8
        manifest['files']=[{'path':str(p.relative_to(out/'overlay')),'bytes':p.stat().st_size,'SHA256':sha(p.read_bytes())}for p in sorted((out/'overlay').rglob('*'))if p.is_file()]
        manifest['resource_memory']={'maximum_expanded_bytes':max(r['expanded_bytes']for g in [1,2,3]for r in parsed[g][2]),'original_Audio_SQUARE_expanded_bytes':parsed[4][2][0]['expanded_bytes'],'all_resources_loaded_simultaneously_proven':False,'physical_256MiB_headroom_proven':False}
        manifest['coverage_scope']='All8distinctoriginaltheme names, not all12originalvariant/Audio/NAV entries'
        manifest['theme_names']=sorted({e['theme']for b in manifest['banks']for e in b['entries']})
        manifest['selection_metadata_proposal']=[{'HMI_ID':e['target_universal_id'],'name':e['theme'],'offset_area':e['offset_area'],'source_only_not_applied':True}for b in manifest['banks']for e in b['entries']]
        (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    assert all(sha(p.read_bytes())==h for p,h in sources.items())
    (out/'source-integrity.json').write_text(json.dumps({'source_files_sha256_unchanged':True,'source_files':{str(p.relative_to(ROOT)):h for p,h in sources.items()}},indent=2)+'\n')
    print(json.dumps({'output':str(out.relative_to(ROOT)),'unique_names':inventory['unique_names'],'original_entries':len(rows),'asset_candidate_built':a.build,'native_activation_tested':False}))

if __name__=='__main__':main()
