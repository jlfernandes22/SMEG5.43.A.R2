#!/usr/bin/env python3
"""Extract missing native windows and stage QEMU-only harmony containers.

Window fragments are analysis files, not standalone installable assets. Native
resources include shared images and indexes, so the candidate uses complete
matching NAV resources inside the original single-entry Audio bank structure.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import zlib

from inspect_internet_harmony import ROOT, PACKAGE, PAGE, bank
from smeg_db_inf import crc16


def sha(data): return hashlib.sha256(data).hexdigest()


def refresh_inf(original, payload, header_crc):
    assert int(original[:4],16)==crc16(original[4:])
    body=original[8:]
    import re
    signed=header_crc if header_crc<2**31 else header_crc-2**32
    body,count=re.subn(rb'(?m)^HEADER_CRC32:[^\r\n]*',b'HEADER_CRC32:'+str(signed).encode(),body)
    assert count==1
    tail=f'{crc16(payload):04x}'.encode()+body
    result=f'{crc16(tail):04x}'.encode()+tail
    assert int(result[:4],16)==crc16(result[4:]) and int(result[4:8],16)==crc16(payload)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    out=a.output.resolve();assert out.is_relative_to(ROOT/'artifacts/phase13') and not out.exists()
    out.mkdir(parents=True)
    _,_,nav=bank(3)
    report={'emulator_only':True,'physical_car_approved':False,
            'standalone_SYSTEM_DATA_theme_files_exist':False,
            'resource_replacement_scope':'Complete NAV SQUARE/WARMLIGHT resources, not a23-window-only production overlay.',
            'banks':[]}
    for group,nav_index in [(4,0),(5,1)]:
        audio,values,audio_rows=bank(group);resource=nav[nav_index]
        assert len(audio_rows)==1 and audio_rows[0]['theme']==resource['theme']
        raw=zlib.decompress(resource['_payload'][4:])
        count,base=struct.unpack_from('>II',raw,4)
        directory=[struct.unpack_from('>4I',raw,0x6c+i*16) for i in range(count)]
        existing={w[1] for w in audio_rows[0]['internet_windows']}
        missing=[w for w in directory if w[0]==8 and w[1] not in existing]
        assert len(missing)==23
        entries=[];fragment_dir=out/'analysis-fragments'/resource['theme'];fragment_dir.mkdir(parents=True)
        for app,screen,offset,flags in missing:
            start=base+offset
            end=min([base+w[2] for w in directory if base+w[2]>start]+[len(raw)])
            fragment=raw[start:end];target=fragment_dir/f'app{app:02d}-screen{screen:02d}.window.bin';target.write_bytes(fragment)
            entries.append({'application':app,'screen':screen,'expanded_offset':hex(start),
                            'bytes':len(fragment),'sha256':sha(fragment),'analysis_fragment':str(target.relative_to(ROOT)),
                            'installable_standalone':False})
        prefix=bytearray(audio[:2*PAGE]);payload=resource['_payload']
        struct.pack_into('>III',prefix,0x824+0xcc,2,len(payload),zlib.crc32(payload))
        header_size=int(values['HEADER_SIZE']);header_crc=zlib.crc32(prefix[PAGE:PAGE+header_size])
        packaged=bytes(prefix)+payload;packaged+=b'\xff'*(-len(packaged)%PAGE)
        target=out/'overlay/HARMONY'/f'BigHarmony_{group}'/'BIG_HARMONY.bin';target.parent.mkdir(parents=True)
        target.write_bytes(packaged)
        original_inf=(PACKAGE/f'BigHarmony_{group}/BIG_HARMONY.bin.inf').read_bytes()
        assert int(original_inf[4:8],16)==crc16(audio)
        inf=refresh_inf(original_inf,packaged,header_crc);Path(str(target)+'.inf').write_bytes(inf)
        assert zlib.decompress(packaged[4096+4:])==raw
        report['banks'].append({'theme':resource['theme'],
            'source_container':'SMEG_PLUS_UPG/HARMONY/BigHarmony_3/BIG_HARMONY.bin',
            'source_entry_index':nav_index,'source_payload_crc32':resource['compressed_crc32_verified'],
            'target_container':str(target.relative_to(out/'overlay')),'target_sha256':sha(packaged),
            'single_entry_Audio_header_preserved':True,'native_INF_crc16_valid':True,
            'header_crc32':f'{header_crc:08x}','missing_windows':entries,
            'unchanged_auxiliary_skin_indexes':'Original BIG_SKIN_AUDIO.bin/BIG_SKIN_NAV.bin retained; full native installer compatibility still untested.'})
    (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'manifest':str(out/'manifest.json'),'extracted_window_fragments':46,'native_harmony_candidates':2,'physical_car_approved':False}))


if __name__=='__main__':main()
